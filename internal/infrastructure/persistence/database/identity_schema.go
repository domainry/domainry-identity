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
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/base"
	migrationcontract "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/platform/config"
	"github.com/domainry/domainry-orm/query"
	ormschema "github.com/domainry/domainry-orm/schema"
)

const (
	CurrentIdentitySchemaVersion           = "011_totp_authentication"
	EmbeddedIdentitySchemaMigrationVersion = uint(11)
	EmbeddedIdentitySchemaMigrationName    = "totp_authentication"
)

const (
	managedIdentityDatabaseTable           = "_identity_managed_database"
	managedIdentityDatabaseContractVersion = "domainry-managed-identity-database-v1"
	identitySchemaMigrationKind            = "identity_schema"
	identitySchemaMigrationName            = "identity_schema"
)

func SupportedIdentitySchemaVersions() []string {
	return []string{CurrentIdentitySchemaVersion}
}

func (s *IdentityStore) EnsureSchema(ctx context.Context) error {
	if s.config.EffectiveDatabaseMigrationMode() == "verify" {
		if err := s.verifyIdentitySchema(ctx); err != nil {
			return err
		}
		if err := s.verifyManagedIdentityDatabaseMarker(ctx); err != nil {
			return err
		}
		return nil
	}
	if s.migrationDB != nil {
		migrationStore := s.identityMigrationStore()
		if err := migrationStore.EnsureSchema(ctx); err != nil {
			return err
		}
		return s.ensureMetadataModuleSchema(ctx)
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
	if err := s.recordIdentitySchemaMigrationIfPending(ctx, pending, startedAt); err != nil {
		return err
	}
	return nil
}

func (s *IdentityStore) EnsureEmbeddedSchema(ctx context.Context) error {
	if err := s.ensureManagedIdentityDatabaseMarker(ctx); err != nil {
		return err
	}
	if err := s.EnsureMetadataSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureIdentitySchema(ctx); err != nil {
		return err
	}
	// Nested Audit owns its migrations and submits them after this outer
	// Identity migration callback releases the Runtime migration lock.
	if err := identityschema.EnsureEvidenceSchema(ctx, s); err != nil {
		return err
	}
	return nil
}

func EmbeddedSchemaChecksum() string { return currentIdentitySchemaChecksum() }

func (s *IdentityStore) identityMigrationStore() *IdentityStore {
	sqlDatabase := base.NewSQLDatabase(s.migrationDB, s.engine, s.databaseSchema, s.relationPrefix)
	return &IdentityStore{
		SQLDatabase:          sqlDatabase,
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
	queryValue, arguments, err := query.NewSelectBuilder(s.BuilderRenderer(), "_schema_migrations").
		Columns("checksum", "dirty").
		Where(query.Equal("path", identitySchemaMigrationPath(CurrentIdentitySchemaVersion))).
		Limit(1).Build()
	if err != nil {
		return fmt.Errorf("build Identity schema compatibility query: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, queryValue, arguments...).Scan(&checksum, &dirty); err != nil {
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
	path := identitySchemaMigrationPath(version)
	var count int
	countStatement, countArguments, err := query.NewSelectBuilder(s.BuilderRenderer(), "_schema_migrations").
		Projections(query.Project(query.CountAll())).Where(query.Equal("path", path)).Build()
	if err != nil {
		return false, fmt.Errorf("build Identity schema migration count: %w", err)
	}
	if err := db.QueryRowContext(ctx, countStatement, countArguments...).Scan(&count); err != nil {
		return false, fmt.Errorf("check Identity schema migration: %w", err)
	}
	if count == 0 {
		return true, nil
	}
	var checksum string
	var dirty bool
	lookupStatement, lookupArguments, err := query.NewSelectBuilder(s.BuilderRenderer(), "_schema_migrations").
		Columns("checksum", "dirty").Where(query.Equal("path", path)).Limit(1).Build()
	if err != nil {
		return false, fmt.Errorf("build Identity schema migration lookup: %w", err)
	}
	if err := db.QueryRowContext(ctx, lookupStatement, lookupArguments...).Scan(&checksum, &dirty); err != nil {
		return false, err
	}
	if dirty {
		return false, fmt.Errorf("migration.dirty: Identity schema %s", version)
	}
	if strings.TrimSpace(checksum) == "" {
		statement, arguments, buildErr := query.NewUpdateBuilder(s.BuilderRenderer(), "_schema_migrations").
			Set("checksum", currentIdentitySchemaChecksum()).Where(query.Equal("path", path)).Build()
		if buildErr != nil {
			return false, fmt.Errorf("build Identity schema checksum backfill: %w", buildErr)
		}
		_, execErr := db.ExecContext(ctx, statement, arguments...)
		return false, execErr
	}
	if checksum != currentIdentitySchemaChecksum() {
		return false, fmt.Errorf("migration.checksum_drift: Identity schema %s", version)
	}
	return false, nil
}

func (s *IdentityStore) startIdentitySchemaMigration(ctx context.Context, version string) error {
	queryValue, arguments, err := query.NewInsertBuilder(s.BuilderRenderer(), "_schema_migrations").
		Columns("path", "version", "name", "kind", "checksum", "dirty", "applied_at", "service_version", "duration_ms", "operator", "instance_id", "backup_id").
		Values(identitySchemaMigrationPath(version), version, identitySchemaMigrationName, identitySchemaMigrationKind, currentIdentitySchemaChecksum(), true, time.Now().UTC().Format(time.RFC3339), s.config.ServiceVersion, 0, migrationcontract.Operator(s.config), migrationcontract.InstanceID(s.config), s.BackupManager.BackupID()).Build()
	if err != nil {
		return fmt.Errorf("build Identity schema migration start: %w", err)
	}
	_, err = s.schemaDatabase().ExecContext(ctx, queryValue, arguments...)
	return err
}

func (s *IdentityStore) recordIdentitySchemaMigration(ctx context.Context, version string, duration time.Duration) error {
	statement, arguments, buildErr := query.NewUpdateBuilder(s.BuilderRenderer(), "_schema_migrations").
		Set("dirty", false).
		Set("duration_ms", duration.Milliseconds()).
		Set("applied_at", time.Now().UTC().Format(time.RFC3339)).
		Where(query.Equal("path", identitySchemaMigrationPath(version))).Build()
	if buildErr != nil {
		return fmt.Errorf("build Identity schema migration completion: %w", buildErr)
	}
	_, err := s.schemaDatabase().ExecContext(ctx, statement, arguments...)
	if err != nil {
		return fmt.Errorf("record Identity schema migration: %w", err)
	}
	return nil
}

func identitySchemaMigrationPath(version string) string {
	return "identity_schema_" + strings.TrimSpace(version)
}

func (s *IdentityStore) identityTableExists(ctx context.Context, table string) (bool, error) {
	var count int
	queryValue := s.PersistenceEngine().TableExistsQuery(s.BuilderRenderer(), s.DatabaseSchema(), s.relationPrefix+table)
	if strings.TrimSpace(queryValue.Statement) == "" {
		return false, fmt.Errorf("Identity table inspection is unavailable")
	}
	if err := s.schemaDatabase().QueryRowContext(ctx, queryValue.Statement, queryValue.Arguments...).Scan(&count); err != nil {
		return false, fmt.Errorf("inspect Identity table %s: %w", table, err)
	}
	return count > 0, nil
}

func (s *IdentityStore) SchemaTableExists(ctx context.Context, table string) (bool, error) {
	return s.identityTableExists(ctx, table)
}

func currentIdentitySchemaChecksum() string {
	sum := sha256.Sum256([]byte(CurrentIdentitySchemaVersion + ":metadata,identity,audit,authentication,applications,permissions,workspace_write_fences,handler_delivery,store_organization_delivery,organization_unit_delivery,organization_unit_sibling_identity,workspace_identity_usage_active_roles,workspace_identity_bootstrap_v1,installation_administrator_bootstrap,managed_database"))
	return hex.EncodeToString(sum[:])
}

func (s *IdentityStore) ensureManagedIdentityDatabaseMarker(ctx context.Context) error {
	if !s.sqlBase().Engine.ManagedDatabaseMarkerEnabled() {
		return nil
	}
	database := s.schemaDatabase()
	statement, arguments, err := ormschema.NewTable(s.BuilderRenderer(), managedIdentityDatabaseTable).
		IfNotExists().
		Columns(
			ormschema.Column("marker_id", ormschema.SmallInt()).NotNull(),
			ormschema.Column("contract_version", ormschema.Varchar(128)).NotNull(),
			ormschema.Column("database_identity_sha256", ormschema.Varchar(64)).NotNull(),
		).
		PrimaryKey("marker_id").Build()
	if err != nil {
		return fmt.Errorf("build managed database cohort marker schema: %w", err)
	}
	if _, err := database.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("prepare managed database cohort marker: %w", err)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("generate managed database cohort marker: %w", err)
	}
	identity := sha256.Sum256(seed)
	insert, arguments, err := query.NewInsertBuilder(s.sqlBase().SQLRenderer, managedIdentityDatabaseTable).
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
	queryValue, arguments, err := query.NewSelectBuilder(s.BuilderRenderer(), managedIdentityDatabaseTable).
		Columns("contract_version", "database_identity_sha256").Where(query.Equal("marker_id", 1)).Limit(1).Build()
	if err != nil {
		return fmt.Errorf("build managed database cohort marker verification: %w", err)
	}
	if err := database.QueryRowContext(ctx, queryValue, arguments...).Scan(&contractVersion, &identity); err != nil {
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

func (s *IdentityStore) columnDefinition(definition string) string {
	return s.sqlBase().Engine.ColumnDefinition(definition)
}
