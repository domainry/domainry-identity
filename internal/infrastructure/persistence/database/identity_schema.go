package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	shareddefinition "github.com/domainry/domainry-foundation/definition"
	sharedoperation "github.com/domainry/domainry-foundation/operation"
	sharedsubject "github.com/domainry/domainry-foundation/subjectlifecycle"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/base"
	migrationcontract "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/platform/config"
	"github.com/domainry/domainry-orm/query"
)

const (
	CurrentIdentitySchemaVersion           = "001_identity_schema"
	EmbeddedIdentitySchemaMigrationVersion = uint(1)
	EmbeddedIdentitySchemaMigrationName    = "create_identity_schema"
)

const (
	identitySchemaMigrationKind = "identity_schema"
	identitySchemaMigrationName = "identity_schema"
)

func SupportedIdentitySchemaVersions() []string {
	return []string{CurrentIdentitySchemaVersion}
}

func (s *IdentityStore) EnsureSchema(ctx context.Context) error {
	if s.config.EffectiveDatabaseMigrationMode() == "verify" {
		return s.verifyIdentitySchema(ctx)
	}
	if s.migrationDB != nil {
		migrationStore := s.identityMigrationStore()
		return migrationStore.EnsureSchema(ctx)
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
	if err := s.ensureDefinitionsKernelLocked(ctx); err != nil {
		return err
	}
	if err := s.EnsureMetadataSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureIdentitySchema(ctx); err != nil {
		return err
	}
	if err := s.ensureOperationsKernelLocked(ctx); err != nil {
		return err
	}
	if err := s.ensureSubjectLifecycleKernelLocked(ctx); err != nil {
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
	EnsureOperationsSchema(context.Context, identityschema.Store) error
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

func (s *IdentityStore) EnsureOperationsSchema(ctx context.Context) error {
	if s.schemaAssembler != nil {
		return s.schemaAssembler.EnsureOperationsSchema(ctx, s)
	}
	migrations, err := sharedoperation.SchemaMigrationsForDialect(s.SchemaRenderer())
	if err != nil {
		return err
	}
	if s.hostModuleMigrations != nil {
		return s.hostModuleMigrations.ApplyOwnedMigrations(ctx, sharedoperation.MigrationOwner, migrations)
	}
	return s.ApplyOwnedMigrations(ctx, sharedoperation.MigrationOwner, migrations)
}

func (s *IdentityStore) EnsureDefinitionsSchema(ctx context.Context) error {
	migrations, err := shareddefinition.SchemaMigrationsForDialect(s.SchemaRenderer())
	if err != nil {
		return err
	}
	if s.hostModuleMigrations != nil {
		return s.hostModuleMigrations.ApplyOwnedMigrations(ctx, shareddefinition.MigrationOwner, migrations)
	}
	return s.ApplyOwnedMigrations(ctx, shareddefinition.MigrationOwner, migrations)
}

func (s *IdentityStore) EnsureSubjectLifecycleSchema(ctx context.Context) error {
	migrations, err := sharedsubject.SchemaMigrationsForDialect(s.SchemaRenderer())
	if err != nil {
		return err
	}
	if s.hostModuleMigrations != nil {
		return s.hostModuleMigrations.ApplyOwnedMigrations(ctx, sharedsubject.MigrationOwner, migrations)
	}
	return s.ApplyOwnedMigrations(ctx, sharedsubject.MigrationOwner, migrations)
}

func (s *IdentityStore) ensureDefinitionsKernelLocked(ctx context.Context) error {
	migrations, err := shareddefinition.SchemaMigrationsForDialect(s.SchemaRenderer())
	if err != nil {
		return err
	}
	return s.ApplyOwnedMigrationsLocked(ctx, shareddefinition.MigrationOwner, migrations)
}

func (s *IdentityStore) ensureOperationsKernelLocked(ctx context.Context) error {
	if s.schemaAssembler != nil {
		return s.schemaAssembler.EnsureOperationsSchema(ctx, s)
	}
	migrations, err := sharedoperation.SchemaMigrationsForDialect(s.SchemaRenderer())
	if err != nil {
		return err
	}
	return s.ApplyOwnedMigrationsLocked(ctx, sharedoperation.MigrationOwner, migrations)
}

func (s *IdentityStore) ensureSubjectLifecycleKernelLocked(ctx context.Context) error {
	migrations, err := sharedsubject.SchemaMigrationsForDialect(s.SchemaRenderer())
	if err != nil {
		return err
	}
	return s.ApplyOwnedMigrationsLocked(ctx, sharedsubject.MigrationOwner, migrations)
}

func (s *IdentityStore) EnsureEvidenceSchema(ctx context.Context) error {
	if s.schemaAssembler != nil {
		return s.schemaAssembler.EnsureEvidenceSchema(ctx, s)
	}
	return identityschema.EnsureEvidenceSchema(ctx, s)
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
		Values(identitySchemaMigrationPath(version), version, identitySchemaMigrationName, identitySchemaMigrationKind, currentIdentitySchemaChecksum(), true, time.Now().UTC().UnixMilli(), s.config.ServiceVersion, 0, migrationcontract.Operator(s.config), migrationcontract.InstanceID(s.config), s.BackupManager.BackupID()).Build()
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
		Set("applied_at", time.Now().UTC().UnixMilli()).
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
	sum := sha256.Sum256([]byte(CurrentIdentitySchemaVersion + ":final_identity_schema"))
	return hex.EncodeToString(sum[:])
}

func (s *IdentityStore) columnDefinition(definition string) string {
	return s.sqlBase().Engine.ColumnDefinition(definition)
}
