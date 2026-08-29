package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ormdialect "github.com/domainry/domainry-orm/dialect"

	migrationcontract "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/observability"
	persistencedriver "github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestMigrationHelpersCoverDialectAndFilesystemEdges(t *testing.T) {
	if got := migrationcontract.DurationMilliseconds(1500 * time.Millisecond); got != "1500ms" {
		t.Fatalf("durationMilliseconds=%q", got)
	}
	if version, name := migrationcontract.Identity("plain.sql"); version != "plain" || name != "plain" {
		t.Fatalf("migrationIdentity=%q,%q", version, name)
	}

	mysqlStore := &IdentityStore{engine: mysql.NewEngine()}
	attachLedger(mysqlStore)
	if sql := mysqlStore.Ledger.SchemaSQL(); !strings.Contains(sql, "VARCHAR(255)") || !strings.Contains(sql, "VARCHAR(64)") {
		t.Fatalf("mysql ledger SQL=%q", sql)
	}
	postgresStore := &IdentityStore{engine: postgres.NewEngine(), databaseSchema: "runtime"}
	attachLedger(postgresStore)
	if sql := postgresStore.Ledger.SchemaSQL(); strings.Contains(sql, "VARCHAR(255)") || !strings.Contains(sql, `"_schema_migrations"`) {
		t.Fatalf("postgres ledger SQL=%q", sql)
	}

	dir := t.TempDir()
	if paths, err := migrationcontract.NewPathResolver(sqlite.NewEngine(), nil).Paths(config.Config{MigrationDir: filepath.Join(dir, "missing")}); err != nil || paths != nil {
		t.Fatalf("missing migration directory paths=%v err=%v", paths, err)
	}
	blocked := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := migrationcontract.NewPathResolver(sqlite.NewEngine(), nil).Paths(config.Config{MigrationDir: blocked}); err == nil {
		t.Fatal("file used as migration directory was accepted")
	}
	entriesDir := filepath.Join(dir, "entries")
	if err := os.MkdirAll(filepath.Join(entriesDir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entriesDir, "ignored.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(entriesDir)
	if err != nil {
		t.Fatal(err)
	}
	if paths := migrationcontract.SQLPaths(entriesDir, entries); paths != nil {
		t.Fatalf("non-SQL entries paths=%v", paths)
	}

	missing := filepath.Join(dir, "missing.sql")
	store := &IdentityStore{}
	if err := store.setExpectedMigrations([]string{missing}); err == nil || !strings.Contains(err.Error(), "read migration checksum") {
		t.Fatalf("setExpectedMigrations error=%v", err)
	}
}

func TestMigrationBackupAndTableDiscoveryRejectInvalidInputs(t *testing.T) {
	for _, test := range []struct{ driver, evidence, want string }{
		{driver: "sqlite", want: "unsupported database driver"},
		{driver: "postgres", want: "MIGRATION_BACKUP_EVIDENCE_PATH"},
		{driver: "mysql", evidence: filepath.Join(t.TempDir(), "missing.json"), want: "read backup evidence"},
	} {
		if _, err := migrationcontract.ValidateExternalBackup(test.driver, test.evidence); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("driver=%q error=%v want=%q", test.driver, err, test.want)
		}
	}

	store := &IdentityStore{engine: sqlite.NewEngine()}
	attachBackupManager(store, nil)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.CreateSQLiteMigrationBackup(cancelled, config.Config{}); err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("cancelled backup error=%v", err)
	}
	if _, err := store.CreateSQLiteMigrationBackup(t.Context(), config.Config{DBPath: ":memory:"}); err == nil || !strings.Contains(err.Error(), "not a copyable file path") {
		t.Fatalf("memory backup error=%v", err)
	}

	unsupported := &IdentityStore{engine: unsupportedMigrationDialect{Engine: sqlite.NewEngine()}}
	attachBackupManager(unsupported, nil)
	if _, err := unsupported.ApplicationTables(t.Context()); err == nil || !strings.Contains(err.Error(), "unsupported database driver") {
		t.Fatalf("applicationTables error=%v", err)
	}
}

func TestValidateExternalMigrationBackupAcceptsMatchingEvidence(t *testing.T) {
	now := time.Now().UTC()
	evidence := migrationcontract.BackupEvidence{
		EvidenceVersion: "v1", BackupID: "backup-1", Engine: "postgres", BackupType: "full", Provider: "test",
		Region: "test-region", FaultDomain: "test-zone", Owner: "identity", CreatedAt: now.Add(-time.Hour), VerifiedAt: now.Add(-time.Minute),
		SchemaVersion: "001", Checksum: "checksum", Size: 1, Encrypted: true, ImmutableUntil: now.Add(time.Hour), RTOSeconds: 60, IntegrityOK: true,
		Artifacts: []migrationcontract.Artifact{
			{Kind: migrationcontract.ArtifactDatabase, Checksum: "database", Size: 1},
			{Kind: migrationcontract.ArtifactIdentityManifest, Checksum: "manifest", Size: 1},
			{Kind: migrationcontract.ArtifactSigningKeyVersions, Checksum: "signing-keys", Size: 1},
			{Kind: migrationcontract.ArtifactDataKeyVersions, Checksum: "data-keys", Size: 1},
			{Kind: migrationcontract.ArtifactService, Checksum: "service", Size: 1},
		},
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "backup-evidence.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := migrationcontract.ValidateExternalBackup("postgres", path)
	if err != nil || loaded.BackupID != evidence.BackupID {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if _, err := migrationcontract.ValidateExternalBackup("mysql", path); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("engine mismatch error=%v", err)
	}
	state := &databaseSQLState{querySteps: []databaseSQLQueryStep{
		{columns: []string{"name"}, rows: [][]driver.Value{{"records"}}},
		{columns: []string{"count"}, rows: [][]driver.Value{{int64(1)}}},
	}}
	store := identitySchemaStore(t, state)
	store.engine = postgres.NewEngine()
	store.operationalMetrics = observability.NewMetrics("", "")
	attachBackupManager(store, nil)
	if err := store.BackupManager.EnsureForExistingData(t.Context(), config.Config{MigrationBackupEvidencePath: path}); err != nil {
		t.Fatal(err)
	}
	if !store.BackupManager.Ready() || store.BackupManager.BackupID() != evidence.BackupID || store.operationalMetrics.AgeSnapshot().BackupLastSuccess.IsZero() {
		t.Fatalf("ready=%v id=%q metrics=%+v", store.BackupManager.Ready(), store.BackupManager.BackupID(), store.operationalMetrics.AgeSnapshot())
	}
	store = identitySchemaStore(t, &databaseSQLState{querySteps: []databaseSQLQueryStep{
		{columns: []string{"name"}, rows: [][]driver.Value{{"records"}}},
		{columns: []string{"count"}, rows: [][]driver.Value{{int64(1)}}},
	}})
	store.engine = postgres.NewEngine()
	attachBackupManager(store, nil)
	if err := store.BackupManager.EnsureForExistingData(t.Context(), config.Config{MigrationBackupEvidencePath: path}); err != nil {
		t.Fatalf("external backup without metrics=%v", err)
	}
}

func TestEnsureMigrationBackupCoversEmptyAndExistingSQLiteDatabases(t *testing.T) {
	emptyDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = emptyDB.Close() })
	emptyStore := &IdentityStore{db: emptyDB, engine: sqlite.NewEngine()}
	attachBackupManager(emptyStore, nil)
	if err := emptyStore.BackupManager.EnsureForExistingData(t.Context(), config.Config{}); err != nil {
		t.Fatal(err)
	}
	if !emptyStore.BackupManager.Ready() || emptyStore.BackupManager.BackupID() != "bootstrap-empty" {
		t.Fatalf("empty backup state ready=%v id=%q", emptyStore.BackupManager.Ready(), emptyStore.BackupManager.BackupID())
	}
	if err := emptyStore.BackupManager.EnsureForExistingData(t.Context(), config.Config{}); err != nil {
		t.Fatalf("already-ready backup error=%v", err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "existing.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(t.Context(), `CREATE TABLE customer (id TEXT PRIMARY KEY); INSERT INTO customer (id) VALUES ('one')`); err != nil {
		t.Fatal(err)
	}
	store := &IdentityStore{db: db, engine: sqlite.NewEngine(), operationalMetrics: observability.NewMetrics("", "")}
	attachBackupManager(store, nil)
	if err := store.BackupManager.EnsureForExistingData(t.Context(), config.Config{DBPath: dbPath, MigrationBackupDir: filepath.Join(dir, "backups")}); err != nil {
		t.Fatal(err)
	}
	if !store.BackupManager.Ready() || !strings.HasPrefix(store.BackupManager.BackupID(), "sqlite-") {
		t.Fatalf("existing backup state ready=%v id=%q", store.BackupManager.Ready(), store.BackupManager.BackupID())
	}
	entries, err := os.ReadDir(filepath.Join(dir, "backups"))
	if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".bak.enc") {
		t.Fatalf("backup entries=%v err=%v", entries, err)
	}
	store = &IdentityStore{db: db, engine: sqlite.NewEngine()}
	attachBackupManager(store, nil)
	if err := store.BackupManager.EnsureForExistingData(t.Context(), config.Config{DBPath: dbPath, MigrationBackupDir: filepath.Join(dir, "backups-without-metrics")}); err != nil {
		t.Fatalf("sqlite backup without metrics=%v", err)
	}
}

type unsupportedMigrationDialect struct{ sqlite.Engine }

func (unsupportedMigrationDialect) Name() string                                     { return "unsupported" }
func (unsupportedMigrationDialect) SQLDriver() string                                { return "" }
func (unsupportedMigrationDialect) DSN(config.Config) (string, error)                { return "", nil }
func (unsupportedMigrationDialect) Configure(context.Context, *sql.DB, string) error { return nil }
func (unsupportedMigrationDialect) SQLDialect() ormdialect.Dialect {
	value, _ := ormdialect.New(ormdialect.SQLite)
	return value
}
func (unsupportedMigrationDialect) SchemaMigrationSQL() string { return "" }
func (unsupportedMigrationDialect) ApplicationTablesQuery(ormdialect.Renderer, string) persistencedriver.SchemaQuery {
	return persistencedriver.SchemaQuery{}
}
