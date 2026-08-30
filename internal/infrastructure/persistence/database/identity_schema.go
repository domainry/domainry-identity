package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	auditmodulehost "github.com/domainry/domainry-audit-sdk/modulehost"
	auditmodule "github.com/domainry/domainry-audit/module"
	migrationcontract "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/workspace"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

const (
	IdentitySchemaVersionBaseline           = "001_identity_service_baseline"
	IdentitySchemaVersionPortability        = "002_identity_portability_cutover"
	IdentitySchemaVersionNoFrontend         = "003_remove_frontend_capability_registry"
	IdentitySchemaVersionProviderCredential = "004_workspace_provider_credential_identity"
	CurrentIdentitySchemaVersion            = "005_data_exchange_and_authoring_cleanup"
)

const (
	managedIdentityDatabaseTable           = "_domainry_managed_identity_database"
	managedIdentityDatabaseContractVersion = "domainry-managed-identity-database-v1"
	identitySchemaMigrationKind            = "identity_schema"
	identitySchemaMigrationName            = "data_exchange_and_authoring_cleanup"
)

func SupportedIdentitySchemaVersions() []string {
	return []string{IdentitySchemaVersionBaseline, IdentitySchemaVersionPortability, IdentitySchemaVersionNoFrontend, IdentitySchemaVersionProviderCredential, CurrentIdentitySchemaVersion}
}

func (s *IdentityStore) EnsureSchema(ctx context.Context) error {
	if s.config.EffectiveDatabaseMigrationMode() == "verify" {
		if err := s.verifyIdentitySchema(ctx); err != nil {
			return err
		}
		if err := s.verifyManagedIdentityDatabaseMarker(ctx); err != nil {
			return err
		}
		return s.EnsureWorkspaceRLS(ctx)
	}
	if s.migrationDB != nil {
		migrationStore := s.identityMigrationStore()
		migrationStore.config.DatabaseRLSEnabled = false
		if err := migrationStore.EnsureSchema(ctx); err != nil {
			return err
		}
		return s.EnsureWorkspaceRLS(ctx)
	}
	release, err := s.LockManager.Acquire(ctx, s.config)
	if err != nil {
		return err
	}
	defer release()
	startedAt := time.Now()
	pending, err := s.identitySchemaMigrationPending(ctx, CurrentIdentitySchemaVersion)
	if err != nil {
		return err
	}
	if pending {
		if err := s.ValidateLegacyWorkspaceScopes(ctx); err != nil {
			return err
		}
		if err := s.BackupManager.EnsureForExistingData(ctx, s.identityMigrationConfig()); err != nil {
			return err
		}
		if err := s.startIdentitySchemaMigration(ctx, CurrentIdentitySchemaVersion); err != nil {
			return err
		}
	}
	if err := s.ensureManagedIdentityDatabaseMarker(ctx); err != nil {
		return err
	}
	if err := s.ensureMetadataModuleSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureMetadataSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureIdentitySchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureEvidenceSchema(ctx); err != nil {
		return err
	}
	if pending {
		if err := identityschema.RemoveFrontendCapabilityRegistry(ctx, s); err != nil {
			return err
		}
		if err := s.retireSupersededIdentityTables(ctx); err != nil {
			return err
		}
	}
	if err := s.recordIdentitySchemaMigrationIfPending(ctx, pending, startedAt); err != nil {
		return err
	}
	return s.EnsureWorkspaceRLS(ctx)
}

// EnsureEmbeddedSchema assembles Identity-owned tables while the embedding
// host owns the migration lock and ledger. It intentionally does not create or
// consult Identity's standalone _schema_materializations ledger.
func (s *IdentityStore) EnsureEmbeddedSchema(ctx context.Context) error {
	if err := s.ensureManagedIdentityDatabaseMarker(ctx); err != nil {
		return err
	}
	if err := s.ensureMetadataModuleSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureMetadataSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureIdentitySchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureEvidenceSchema(ctx); err != nil {
		return err
	}
	if err := s.retireSupersededIdentityTables(ctx); err != nil {
		return err
	}
	return s.EnsureWorkspaceRLS(ctx)
}

// retireSupersededIdentityTables removes Data Exchange job state, retired
// metadata draft storage, and the write-fence event table superseded by Audit.
// domainry-orm has no DROP TABLE builder; these bounded, host-qualified DDL
// statements run only in the migration boundary.
func (s *IdentityStore) retireSupersededIdentityTables(ctx context.Context) error {
	for _, table := range []string{"identity_portability_export_receipts", "identity_portability_import_receipts", "identity_change_plan_operations", "identity_change_plan_drafts", "identity_portability_write_fence_events"} {
		if _, err := s.schemaDatabase().ExecContext(ctx, "DROP TABLE IF EXISTS "+s.tableIdentifier(table)); err != nil {
			return fmt.Errorf("retire superseded Identity table %s: %w", table, err)
		}
	}
	return nil
}

func EmbeddedSchemaChecksum() string { return currentIdentitySchemaChecksum() }

func (s *IdentityStore) identityMigrationStore() *IdentityStore {
	return &IdentityStore{
		RLSManager:           s.RLSManager,
		ScopeValidator:       workspace.NewScopeValidator(s.migrationDB, s.engine, s.BuilderRenderer(), s.databaseSchema, s.relationPrefix),
		Coordinator:          s.Coordinator,
		db:                   s.migrationDB,
		engine:               s.engine,
		config:               s.config,
		databaseSchema:       s.databaseSchema,
		postgresProfile:      s.postgresProfile,
		postgresCapabilities: s.postgresCapabilities,
		migratorCapabilities: s.migratorCapabilities,
		secretMaterialKey:    s.secretMaterialKey,
		secretKeyProvider:    s.secretKeyProvider,
		migrationCompatible:  s.migrationCompatible,
		idempotencyMetrics:   s.idempotencyMetrics,
		sqlMetrics:           s.sqlMetrics,
		operationalMetrics:   s.operationalMetrics,
		schemaAssembler:      s.schemaAssembler,
	}
}

func (s *IdentityStore) recordIdentitySchemaMigrationIfPending(ctx context.Context, pending bool, startedAt time.Time) error {
	if !pending {
		return nil
	}
	return s.recordIdentitySchemaMigration(ctx, CurrentIdentitySchemaVersion, time.Since(startedAt))
}

func (s *IdentityStore) verifyIdentitySchema(ctx context.Context) error {
	var checksum string
	var dirty bool
	query := "SELECT " + s.identifier("checksum") + ", " + s.identifier("dirty") + " FROM " + s.tableIdentifier("_schema_migrations") + " WHERE " + s.identifier("path") + " = " + s.placeholder(1)
	if err := s.db.QueryRowContext(ctx, query, identitySchemaMigrationPath(CurrentIdentitySchemaVersion)).Scan(&checksum, &dirty); err != nil {
		return fmt.Errorf("verify Identity schema compatibility: %w", err)
	}
	if dirty {
		return fmt.Errorf("migration.dirty: Identity schema %s", CurrentIdentitySchemaVersion)
	}
	if checksum != currentIdentitySchemaChecksum() {
		return fmt.Errorf("migration.checksum_drift: Identity schema %s", CurrentIdentitySchemaVersion)
	}
	return nil
}

type schemaDatabase = identityschema.SQLDatabase

type identitySchemaAssembler interface {
	EnsureMetadataSchema(context.Context, identityschema.Store) error
	EnsureIdentitySchema(context.Context, identityschema.Store) error
	EnsureEvidenceSchema(context.Context, identityschema.Store) error
}

func (s *IdentityStore) schemaDatabase() schemaDatabase {
	if s.LockManager != nil && s.LockManager.Connection() != nil {
		return s.LockManager.Connection()
	}
	if s.migrationDB != nil {
		return s.migrationDB
	}
	return s.db
}

// SchemaDB returns the advisory-lock-owning migration connection when schema
// assembly is running, so a one-connection migrator pool cannot self-deadlock.
func (s *IdentityStore) SchemaDB() identityschema.SQLDatabase {
	return s.schemaDatabase()
}

func (s *IdentityStore) EnsureMetadataSchema(ctx context.Context) error {
	if s.schemaAssembler != nil {
		return s.schemaAssembler.EnsureMetadataSchema(ctx, s)
	}
	return identityschema.EnsureMetadataSchema(ctx, s)
}

func (s *IdentityStore) EnsureIdentitySchema(ctx context.Context) error {
	if s.schemaAssembler != nil {
		return s.schemaAssembler.EnsureIdentitySchema(ctx, s)
	}
	return identityschema.EnsureIdentitySchema(ctx, s)
}

func (s *IdentityStore) EnsureEvidenceSchema(ctx context.Context) error {
	if s.schemaAssembler != nil {
		return s.schemaAssembler.EnsureEvidenceSchema(ctx, s)
	}
	binding, err := auditmodule.NewFactory(auditmodule.Options{}).OpenModule(ctx, auditsdk.ApplicationRef{InstallationID: "domainry-identity"}, identityAuditLockedHost{store: s})
	if err != nil {
		return fmt.Errorf("prepare Audit module schema: %w", err)
	}
	defer binding.Close(ctx)
	return identityschema.EnsureEvidenceSchema(ctx, s)
}

type identityAuditLockedHost struct{ store *IdentityStore }

func (h identityAuditLockedHost) Database() auditmodulehost.Database { return h.store.DB() }
func (h identityAuditLockedHost) Dialect() auditmodulehost.Dialect {
	return h.store.BuilderRenderer()
}
func (h identityAuditLockedHost) Migrations() auditmodulehost.MigrationRegistrar {
	return identityAuditLockedMigrationRegistrar{store: h.store}
}

type identityAuditLockedMigrationRegistrar struct{ store *IdentityStore }

func (r identityAuditLockedMigrationRegistrar) Driver() string {
	return r.store.PersistenceEngine().Name()
}
func (r identityAuditLockedMigrationRegistrar) Schema() string { return r.store.DatabaseSchema() }
func (r identityAuditLockedMigrationRegistrar) ApplyOwnedMigrations(ctx context.Context, owner string, migrations []auditmodulehost.SchemaMigration) error {
	return r.store.ApplyOwnedMigrationsLocked(ctx, owner, migrations)
}

func (s *IdentityStore) identityMigrationConfig() config.Config {
	cfg := s.config
	if strings.TrimSpace(cfg.MigrationBackupDir) == "" {
		dbPath := s.sqlBase().Engine.MigrationDatabasePath(cfg)
		if dbPath != "" && dbPath != ":memory:" {
			cfg.MigrationBackupDir = filepath.Join(filepath.Dir(dbPath), "migration-backups")
		}
	}
	return cfg
}

func (s *IdentityStore) identitySchemaMigrationPending(ctx context.Context, version string) (bool, error) {
	db := s.schemaDatabase()
	if s.Coordinator == nil || s.Coordinator.Ledger == nil {
		return false, fmt.Errorf("Identity schema migration ledger is unavailable")
	}
	if err := s.Coordinator.Ledger.Ensure(ctx); err != nil {
		return false, fmt.Errorf("prepare Identity schema migration ledger: %w", err)
	}
	if err := s.adoptLegacyIdentityMaterializationLedger(ctx); err != nil {
		return false, err
	}
	path := identitySchemaMigrationPath(version)
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.tableIdentifier("_schema_migrations")+" WHERE "+s.identifier("path")+" = "+s.placeholder(1), path).Scan(&count); err != nil {
		return false, fmt.Errorf("check Identity schema migration: %w", err)
	}
	if count == 0 {
		return true, nil
	}
	var checksum string
	var dirty bool
	if err := db.QueryRowContext(ctx, "SELECT "+s.identifier("checksum")+", "+s.identifier("dirty")+" FROM "+s.tableIdentifier("_schema_migrations")+" WHERE "+s.identifier("path")+" = "+s.placeholder(1), path).Scan(&checksum, &dirty); err != nil {
		return false, err
	}
	if dirty {
		return false, fmt.Errorf("migration.dirty: Identity schema %s", version)
	}
	if strings.TrimSpace(checksum) == "" {
		_, err := db.ExecContext(ctx, "UPDATE "+s.tableIdentifier("_schema_migrations")+" SET "+s.identifier("checksum")+" = "+s.placeholder(1)+" WHERE "+s.identifier("path")+" = "+s.placeholder(2), currentIdentitySchemaChecksum(), path)
		return false, err
	}
	if checksum != currentIdentitySchemaChecksum() {
		return false, fmt.Errorf("migration.checksum_drift: Identity schema %s", version)
	}
	return false, nil
}

func (s *IdentityStore) startIdentitySchemaMigration(ctx context.Context, version string) error {
	columns := []string{"path", "version", "name", "kind", "checksum", "dirty", "applied_at", "service_version", "duration_ms", "operator", "instance_id", "backup_id"}
	query := "INSERT INTO " + s.tableIdentifier("_schema_migrations") + " (" + strings.Join(quotedColumns(s, columns), ", ") + ") VALUES (" + strings.Join(placeholders(s, len(columns)), ", ") + ")"
	_, err := s.schemaDatabase().ExecContext(ctx, query, identitySchemaMigrationPath(version), version, identitySchemaMigrationName, identitySchemaMigrationKind, currentIdentitySchemaChecksum(), true, time.Now().UTC().Format(time.RFC3339), s.config.ServiceVersion, 0, migrationcontract.Operator(s.config), migrationcontract.InstanceID(s.config), s.BackupManager.BackupID())
	return err
}

func (s *IdentityStore) recordIdentitySchemaMigration(ctx context.Context, version string, duration time.Duration) error {
	_, err := s.schemaDatabase().ExecContext(ctx, "UPDATE "+s.tableIdentifier("_schema_migrations")+" SET "+s.identifier("dirty")+" = FALSE, "+s.identifier("duration_ms")+" = "+s.placeholder(1)+", "+s.identifier("applied_at")+" = "+s.placeholder(2)+" WHERE "+s.identifier("path")+" = "+s.placeholder(3), duration.Milliseconds(), time.Now().UTC().Format(time.RFC3339), identitySchemaMigrationPath(version))
	if err != nil {
		return fmt.Errorf("record Identity schema migration: %w", err)
	}
	return nil
}

func identitySchemaMigrationPath(version string) string {
	return "identity_schema_" + strings.TrimSpace(version)
}

func (s *IdentityStore) adoptLegacyIdentityMaterializationLedger(ctx context.Context) error {
	exists, err := s.identityTableExists(ctx, "_schema_materializations")
	if err != nil || !exists {
		return err
	}
	columns := []string{"version", "name", "kind", "checksum", "dirty", "applied_at", "service_version", "duration_ms", "operator", "instance_id", "backup_id"}
	rows, err := s.schemaDatabase().QueryContext(ctx, "SELECT "+strings.Join(quotedColumns(s, columns), ", ")+" FROM "+s.tableIdentifier("_schema_materializations"))
	if err != nil {
		return fmt.Errorf("read legacy Identity materialization ledger: %w", err)
	}
	type legacyMaterialization struct {
		version, name, kind, checksum, appliedAt, serviceVersion, operator, instanceID, backupID string
		dirty                                                                                    bool
		duration                                                                                 int64
	}
	values := []legacyMaterialization{}
	for rows.Next() {
		var value legacyMaterialization
		if err := rows.Scan(&value.version, &value.name, &value.kind, &value.checksum, &value.dirty, &value.appliedAt, &value.serviceVersion, &value.duration, &value.operator, &value.instanceID, &value.backupID); err != nil {
			_ = rows.Close()
			return err
		}
		values = append(values, value)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, value := range values {
		query, args, buildErr := ormbuilder.NewInsertBuilder(s.BuilderRenderer(), "_schema_migrations").Columns("path", "version", "name", "kind", "checksum", "dirty", "applied_at", "service_version", "duration_ms", "operator", "instance_id", "backup_id").Values(identitySchemaMigrationPath(value.version), value.version, value.name, identitySchemaMigrationKind, value.checksum, value.dirty, value.appliedAt, value.serviceVersion, value.duration, value.operator, value.instanceID, value.backupID).OnConflictDoNothing("path").Build()
		if buildErr != nil {
			return buildErr
		}
		if _, err := s.schemaDatabase().ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("adopt Identity materialization %s: %w", value.version, err)
		}
	}
	// domainry-orm has no DROP TABLE builder. This bounded cleanup retires the
	// former second migration ledger after every row has been adopted.
	if _, err := s.schemaDatabase().ExecContext(ctx, "DROP TABLE "+s.tableIdentifier("_schema_materializations")); err != nil {
		return fmt.Errorf("retire legacy Identity materialization ledger: %w", err)
	}
	return nil
}

func (s *IdentityStore) identityTableExists(ctx context.Context, table string) (bool, error) {
	var count int
	query := s.PersistenceEngine().TableExistsQuery(s.BuilderRenderer(), s.DatabaseSchema(), s.relationPrefix+table)
	if strings.TrimSpace(query.Statement) == "" {
		return false, fmt.Errorf("Identity table inspection is unavailable")
	}
	if err := s.schemaDatabase().QueryRowContext(ctx, query.Statement, query.Arguments...).Scan(&count); err != nil {
		return false, fmt.Errorf("inspect legacy Identity materialization ledger: %w", err)
	}
	return count > 0, nil
}

func (s *IdentityStore) SchemaTableExists(ctx context.Context, table string) (bool, error) {
	return s.identityTableExists(ctx, table)
}

func currentIdentitySchemaChecksum() string {
	sum := sha256.Sum256([]byte(CurrentIdentitySchemaVersion + ":metadata,identity,audit,authentication,authorization_catalog,workspace_provider_credential_identity,data_exchange_and_authoring_cleanup,workspace_write_fences,managed_identity_database,no_frontend_capability_registry"))
	return hex.EncodeToString(sum[:])
}

func (s *IdentityStore) ensureManagedIdentityDatabaseMarker(ctx context.Context) error {
	if !s.sqlBase().Engine.ManagedDatabaseMarkerEnabled() {
		return nil
	}
	database := s.schemaDatabase()
	table := s.tableIdentifier(managedIdentityDatabaseTable)
	statement := "CREATE TABLE IF NOT EXISTS " + table + " (" + s.identifier("marker_id") + " SMALLINT NOT NULL PRIMARY KEY, " + s.identifier("contract_version") + " VARCHAR(128) NOT NULL, " + s.identifier("database_identity_sha256") + " CHAR(64) NOT NULL)"
	if _, err := database.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("prepare managed database cohort marker: %w", err)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("generate managed database cohort marker: %w", err)
	}
	identity := sha256.Sum256(seed)
	insert, arguments, err := ormbuilder.NewInsertBuilder(s.sqlBase().SQLRenderer, managedIdentityDatabaseTable).
		Columns("marker_id", "contract_version", "database_identity_sha256").
		Values(1, managedIdentityDatabaseContractVersion, hex.EncodeToString(identity[:])).
		OnConflictDoNothing("marker_id").
		Build()
	if err != nil {
		return fmt.Errorf("build managed database cohort marker: %w", err)
	}
	if _, err := database.ExecContext(ctx, insert, arguments...); err != nil {
		return fmt.Errorf("initialize managed database cohort marker: %w", err)
	}
	return s.verifyManagedIdentityDatabaseMarkerWith(ctx, database)
}

func (s *IdentityStore) verifyManagedIdentityDatabaseMarker(ctx context.Context) error {
	if !s.sqlBase().Engine.ManagedDatabaseMarkerEnabled() {
		return nil
	}
	return s.verifyManagedIdentityDatabaseMarkerWith(ctx, s.db)
}

func (s *IdentityStore) verifyManagedIdentityDatabaseMarkerWith(ctx context.Context, database schemaDatabase) error {
	var contractVersion, identity string
	query := "SELECT " + s.identifier("contract_version") + ", " + s.identifier("database_identity_sha256") + " FROM " + s.tableIdentifier(managedIdentityDatabaseTable) + " WHERE " + s.identifier("marker_id") + " = " + s.placeholder(1)
	if err := database.QueryRowContext(ctx, query, 1).Scan(&contractVersion, &identity); err != nil {
		return fmt.Errorf("verify managed database cohort marker: %w", err)
	}
	if contractVersion != managedIdentityDatabaseContractVersion || len(identity) != 64 {
		return fmt.Errorf("verify managed database cohort marker: invalid marker identity")
	}
	if _, err := hex.DecodeString(identity); err != nil {
		return fmt.Errorf("verify managed database cohort marker: invalid marker identity")
	}
	return nil
}

func (s *IdentityStore) ensureColumn(ctx context.Context, table, column, definition string) error {
	db := s.schemaDatabase()
	rows, err := db.QueryContext(ctx, "SELECT "+column+" FROM "+s.tableIdentifier(table)+" WHERE 1 = 0")
	if err == nil {
		return rows.Close()
	}
	definition = s.columnDefinition(definition)
	if _, alterErr := db.ExecContext(ctx, "ALTER TABLE "+s.tableIdentifier(table)+" ADD COLUMN "+s.identifier(column)+" "+definition); alterErr != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, alterErr)
	}
	return nil
}

func (s *IdentityStore) columnDefinition(definition string) string {
	return s.sqlBase().Engine.ColumnDefinition(definition)
}
