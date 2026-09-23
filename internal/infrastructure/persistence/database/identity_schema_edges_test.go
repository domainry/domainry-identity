package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/base"
	migrationowner "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func identitySchemaStore(t *testing.T, state *databaseSQLState) *IdentityStore {
	t.Helper()
	db := openDatabaseScriptedDB(state)
	t.Cleanup(func() { _ = db.Close() })
	engine := sqlite.NewEngine()
	sqlDatabase := base.NewSQLDatabase(db, engine, "", "")
	renderer := sqlDatabase.SQLRenderer
	store := &IdentityStore{SQLDatabase: sqlDatabase, db: db, engine: engine}
	store.Coordinator = migrationowner.NewCoordinator(migrationowner.CoordinatorOptions{QueryDatabase: db, ManagementDatabase: db, Engine: engine, Renderer: renderer, StatusReader: migrationowner.NewStatusReader(db, engine, renderer, config.Config{})})
	attachBackupManager(store, nil)
	attachLockManager(store)
	attachLedger(store)
	attachPathResolver(store, nil)
	attachCoordinator(store)
	return store
}

func identitySchemaLedgerQueries(count int64, checksum string, dirty bool) []databaseSQLQueryStep {
	steps := make([]databaseSQLQueryStep, 0, 12)
	for range 10 {
		steps = append(steps, databaseSQLQueryStep{})
	}
	steps = append(steps,
		databaseSQLQueryStep{columns: []string{"count"}, rows: [][]driver.Value{{count}}},
		databaseSQLQueryStep{columns: []string{"checksum", "dirty"}, rows: [][]driver.Value{{checksum, dirty}}},
	)
	return steps
}

func TestIdentitySchemaHelpersAndDatabaseSelection(t *testing.T) {
	versions := SupportedIdentitySchemaVersions()
	if len(versions) != 1 || versions[0] != CurrentIdentitySchemaVersion {
		t.Fatalf("versions=%#v", versions)
	}
	store := identitySchemaStore(t, &databaseSQLState{})
	if store.schemaDatabase() != store.db {
		t.Fatal("primary database not selected")
	}
	migrationDB := openDatabaseScriptedDB(&databaseSQLState{})
	t.Cleanup(func() { _ = migrationDB.Close() })
	store.migrationDB = migrationDB
	if store.schemaDatabase() != migrationDB {
		t.Fatal("migration database not selected")
	}
	store = &IdentityStore{engine: sqlite.NewEngine(), config: config.Config{DBPath: filepath.Join("tmp", "identity.db")}}
	if got := store.identityMigrationConfig().MigrationBackupDir; got != filepath.Join("tmp", "migration-backups") {
		t.Fatalf("backup dir=%q", got)
	}
	store.config = config.Config{DatabaseDSN: filepath.Join("var", "identity.db")}
	if got := store.identityMigrationConfig().MigrationBackupDir; got != filepath.Join("var", "migration-backups") {
		t.Fatalf("dsn backup dir=%q", got)
	}
	store.config.MigrationBackupDir = "custom"
	if got := store.identityMigrationConfig().MigrationBackupDir; got != "custom" {
		t.Fatalf("custom backup dir=%q", got)
	}
	store.config = config.Config{DBPath: ":memory:"}
	if got := store.identityMigrationConfig().MigrationBackupDir; got != "" {
		t.Fatalf("memory backup dir=%q", got)
	}
	store = &IdentityStore{engine: mysql.NewEngine()}
	if got := store.identityMigrationConfig().MigrationBackupDir; got != "" {
		t.Fatalf("mysql backup dir=%q", got)
	}
}

func TestVerifyIdentitySchemaStates(t *testing.T) {
	checksum := currentIdentitySchemaChecksum()
	tests := []struct {
		name  string
		step  databaseSQLQueryStep
		match string
	}{
		{"query", databaseSQLQueryStep{err: errDatabaseSQL}, "verify Identity schema"},
		{"dirty", databaseSQLQueryStep{columns: []string{"checksum", "dirty"}, rows: [][]driver.Value{{checksum, true}}}, "migration.dirty"},
		{"drift", databaseSQLQueryStep{columns: []string{"checksum", "dirty"}, rows: [][]driver.Value{{"drift", false}}}, "checksum_drift"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := identitySchemaStore(t, &databaseSQLState{querySteps: []databaseSQLQueryStep{test.step}})
			if err := store.verifyIdentitySchema(t.Context()); err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	store := identitySchemaStore(t, &databaseSQLState{querySteps: []databaseSQLQueryStep{{columns: []string{"checksum", "dirty"}, rows: [][]driver.Value{{checksum, false}}}}})
	if err := store.verifyIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestIdentitySchemaMigrationLedgerFailures(t *testing.T) {
	store := identitySchemaStore(t, &databaseSQLState{execSteps: []databaseSQLExecStep{{err: errDatabaseSQL}}})
	if _, err := store.identitySchemaMigrationPending(t.Context(), "version"); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("create error=%v", err)
	}
	queries := identitySchemaLedgerQueries(0, "", false)[:11]
	queries[10] = databaseSQLQueryStep{err: errDatabaseSQL}
	store = identitySchemaStore(t, &databaseSQLState{querySteps: queries})
	if _, err := store.identitySchemaMigrationPending(t.Context(), "version"); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("count error=%v", err)
	}
	store = identitySchemaStore(t, &databaseSQLState{querySteps: identitySchemaLedgerQueries(0, "", false)})
	if pending, err := store.identitySchemaMigrationPending(t.Context(), "version"); err != nil || !pending {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	queries = identitySchemaLedgerQueries(0, "", false)[:11]
	store = identitySchemaStore(t, &databaseSQLState{querySteps: queries})
	if pending, err := store.identitySchemaMigrationPending(t.Context(), "version"); err != nil || !pending {
		t.Fatalf("alter success pending=%v err=%v", pending, err)
	}
	for _, test := range []struct {
		name     string
		checksum string
		dirty    bool
		want     string
	}{
		{"dirty", currentIdentitySchemaChecksum(), true, "migration.dirty"},
		{"drift", "drift", false, "checksum_drift"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := identitySchemaStore(t, &databaseSQLState{querySteps: identitySchemaLedgerQueries(1, test.checksum, test.dirty)})
			if _, err := store.identitySchemaMigrationPending(t.Context(), "version"); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	store = identitySchemaStore(t, &databaseSQLState{querySteps: identitySchemaLedgerQueries(1, "", false), execSteps: []databaseSQLExecStep{{rows: 1}, {err: errDatabaseSQL}}})
	if _, err := store.identitySchemaMigrationPending(t.Context(), "version"); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("backfill error=%v", err)
	}
}

func TestIdentitySchemaMutationFailuresAndDefinitions(t *testing.T) {
	store := identitySchemaStore(t, &databaseSQLState{execSteps: []databaseSQLExecStep{{err: errDatabaseSQL}}})
	if err := store.startIdentitySchemaMigration(t.Context(), "version"); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("start=%v", err)
	}
	store = identitySchemaStore(t, &databaseSQLState{execSteps: []databaseSQLExecStep{{err: errDatabaseSQL}}})
	if err := store.recordIdentitySchemaMigration(t.Context(), "version", time.Second); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("record=%v", err)
	}
	mysqlStore := &IdentityStore{engine: mysql.NewEngine()}
	definition := "TEXT NOT NULL DEFAULT '[]', TEXT NOT NULL DEFAULT '{}', TEXT NOT NULL DEFAULT ''"
	got := mysqlStore.columnDefinition(definition)
	for _, expected := range []string{"DEFAULT ('[]')", "DEFAULT ('{}')", "DEFAULT ('')"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("definition=%q", got)
		}
	}
	if got := (&IdentityStore{engine: sqlite.NewEngine()}).columnDefinition(definition); got != definition {
		t.Fatalf("sqlite definition=%q", got)
	}
}

type identitySchemaAssemblerStub struct{ fail string }

func (stub identitySchemaAssemblerStub) result(stage string) error {
	if stub.fail == stage {
		return errDatabaseSQL
	}
	return nil
}
func (stub identitySchemaAssemblerStub) EnsureMetadataSchema(context.Context, identityschema.Store) error {
	return stub.result("metadata")
}
func (stub identitySchemaAssemblerStub) EnsureIdentitySchema(context.Context, identityschema.Store) error {
	return stub.result("identity")
}
func (stub identitySchemaAssemblerStub) EnsureOperationsSchema(context.Context, identityschema.Store) error {
	return stub.result("operations")
}
func (stub identitySchemaAssemblerStub) EnsureEvidenceSchema(context.Context, identityschema.Store) error {
	return stub.result("evidence")
}

func TestEnsureIdentitySchemaAssemblerFailures(t *testing.T) {
	for _, stage := range []string{"metadata", "identity", "operations", "evidence"} {
		t.Run(stage, func(t *testing.T) {
			state := &databaseSQLState{querySteps: identitySchemaLedgerQueries(1, currentIdentitySchemaChecksum(), false)}
			store := identitySchemaStore(t, state)
			store.schemaAssembler = identitySchemaAssemblerStub{fail: stage}
			if err := store.EnsureSchema(t.Context()); !errors.Is(err, errDatabaseSQL) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestEnsureIdentitySchemaOrchestrationFailures(t *testing.T) {
	verify := identitySchemaStore(t, &databaseSQLState{querySteps: []databaseSQLQueryStep{{err: errDatabaseSQL}}})
	verify.config.DatabaseMigrationMode = "verify"
	if err := verify.EnsureSchema(t.Context()); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("verify error=%v", err)
	}

	primary := identitySchemaStore(t, &databaseSQLState{})
	closedMigration := openDatabaseScriptedDB(&databaseSQLState{})
	_ = closedMigration.Close()
	primary.migrationDB = closedMigration
	if err := primary.EnsureSchema(t.Context()); err == nil {
		t.Fatal("closed migration database was accepted")
	}

	locked := identitySchemaStore(t, &databaseSQLState{})
	locked.config.DBPath = filepath.Join("/dev/null", "identity.db")
	if err := locked.EnsureSchema(t.Context()); err == nil {
		t.Fatal("invalid migration lock path was accepted")
	}

	pendingFailure := identitySchemaStore(t, &databaseSQLState{execSteps: []databaseSQLExecStep{{err: errDatabaseSQL}}})
	if err := pendingFailure.EnsureSchema(t.Context()); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("pending error=%v", err)
	}

	pendingLedgerQueries := identitySchemaLedgerQueries(0, "", false)[:11]
	validationQueries := append(append([]databaseSQLQueryStep{}, pendingLedgerQueries...), databaseSQLQueryStep{err: errDatabaseSQL})
	validation := identitySchemaStore(t, &databaseSQLState{querySteps: validationQueries})
	if err := validation.EnsureSchema(t.Context()); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("validation error=%v", err)
	}

	backupQueries := append(append([]databaseSQLQueryStep{}, pendingLedgerQueries...), databaseSQLQueryStep{}, databaseSQLQueryStep{err: errDatabaseSQL})
	backup := identitySchemaStore(t, &databaseSQLState{querySteps: backupQueries})
	if err := backup.EnsureSchema(t.Context()); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("backup error=%v", err)
	}

	recordQueries := append(append([]databaseSQLQueryStep{}, pendingLedgerQueries...), databaseSQLQueryStep{}, databaseSQLQueryStep{})
	record := identitySchemaStore(t, &databaseSQLState{querySteps: recordQueries, execSteps: []databaseSQLExecStep{{rows: 1}, {rows: 1}, {err: errDatabaseSQL}}})
	record.schemaAssembler = identitySchemaAssemblerStub{}
	if err := record.EnsureSchema(t.Context()); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("record error=%v", err)
	}

	startQueries := append(append([]databaseSQLQueryStep{}, pendingLedgerQueries...), databaseSQLQueryStep{}, databaseSQLQueryStep{})
	start := identitySchemaStore(t, &databaseSQLState{querySteps: startQueries, execSteps: []databaseSQLExecStep{{rows: 1}, {err: errDatabaseSQL}}})
	if err := start.EnsureSchema(t.Context()); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("start error=%v", err)
	}
}

func TestIdentitySchemaPendingRecordEdges(t *testing.T) {
	store := identitySchemaStore(t, &databaseSQLState{execSteps: []databaseSQLExecStep{{err: errDatabaseSQL}}})
	if err := store.recordIdentitySchemaMigrationIfPending(t.Context(), false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.recordIdentitySchemaMigrationIfPending(t.Context(), true, time.Now()); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("record error=%v", err)
	}
	success := identitySchemaStore(t, &databaseSQLState{execSteps: []databaseSQLExecStep{{rows: 1}}})
	if err := success.recordIdentitySchemaMigrationIfPending(t.Context(), true, time.Now()); err != nil {
		t.Fatalf("successful record error=%v", err)
	}
}

func TestIdentitySchemaMigrationChecksumQueryFailure(t *testing.T) {
	queries := identitySchemaLedgerQueries(1, currentIdentitySchemaChecksum(), false)
	queries[10] = databaseSQLQueryStep{err: errDatabaseSQL}
	store := identitySchemaStore(t, &databaseSQLState{querySteps: queries})
	if _, err := store.identitySchemaMigrationPending(t.Context(), "version"); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("checksum query error=%v", err)
	}
}

func TestSchemaAssemblerSeamMethods(t *testing.T) {
	store := &IdentityStore{schemaAssembler: identitySchemaAssemblerStub{}}
	if err := store.EnsureMetadataSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureEvidenceSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
}

var _ schemaDatabase = (*sql.DB)(nil)
