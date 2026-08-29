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

	migrationcontract "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/workspace"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

const (
	IdentitySchemaVersionBaseline    = "001_identity_service_baseline"
	IdentitySchemaVersionPortability = "002_identity_portability_cutover"
	IdentitySchemaVersionNoFrontend  = "003_remove_frontend_capability_registry"
	CurrentIdentitySchemaVersion     = "004_workspace_provider_credential_identity"
)

const (
	identitySchemaMigrationTable           = "_schema_materializations"
	managedIdentityDatabaseTable           = "_domainry_managed_identity_database"
	managedIdentityDatabaseContractVersion = "domainry-managed-identity-database-v1"
	identitySchemaMigrationKind            = "identity_schema"
	identitySchemaMigrationName            = "workspace_provider_credential_identity"
)

func SupportedIdentitySchemaVersions() []string {
	return []string{IdentitySchemaVersionBaseline, IdentitySchemaVersionPortability, IdentitySchemaVersionNoFrontend, CurrentIdentitySchemaVersion}
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
	release, err := s.acquireMigrationLock(ctx, s.config)
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
		if err := s.ensureMigrationBackupForExistingData(ctx, s.identityMigrationConfig()); err != nil {
			return err
		}
		if err := s.startIdentitySchemaMigration(ctx, CurrentIdentitySchemaVersion); err != nil {
			return err
		}
	}
	if err := s.ensureManagedIdentityDatabaseMarker(ctx); err != nil {
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
	}
	if err := s.recordIdentitySchemaMigrationIfPending(ctx, pending, startedAt); err != nil {
		return err
	}
	return s.EnsureWorkspaceRLS(ctx)
}

func (s *IdentityStore) identityMigrationStore() *IdentityStore {
	return &IdentityStore{
		RLSManager:           s.RLSManager,
		ScopeValidator:       workspace.NewScopeValidator(s.migrationDB, s.engine, s.BuilderRenderer(), s.databaseSchema, s.relationPrefix),
		StatusReader:         s.StatusReader,
		db:                   s.migrationDB,
		engine:               s.engine,
		config:               s.config,
		databaseSchema:       s.databaseSchema,
		postgresProfile:      s.postgresProfile,
		postgresCapabilities: s.postgresCapabilities,
		migratorCapabilities: s.migratorCapabilities,
		secretMaterialKey:    s.secretMaterialKey,
		secretKeyProvider:    s.secretKeyProvider,
		migrationBackupReady: s.migrationBackupReady,
		migrationCompatible:  s.migrationCompatible,
		migrationBackupID:    s.migrationBackupID,
		idempotencyMetrics:   s.idempotencyMetrics,
		sqlMetrics:           s.sqlMetrics,
		operationalMetrics:   s.operationalMetrics,
		schemaAssembler:      s.schemaAssembler,
		backupChecksum:       s.backupChecksum,
		migrationReadDir:     s.migrationReadDir,
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
	query := "SELECT " + s.identifier("checksum") + ", " + s.identifier("dirty") + " FROM " + s.tableIdentifier(identitySchemaMigrationTable) + " WHERE " + s.identifier("version") + " = " + s.placeholder(1)
	if err := s.db.QueryRowContext(ctx, query, CurrentIdentitySchemaVersion).Scan(&checksum, &dirty); err != nil {
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
	if s.migrationConn != nil {
		return s.migrationConn
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
	text := s.metadataIDColumnType()
	if _, err := db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.tableIdentifier(identitySchemaMigrationTable)+" ("+s.identifier("version")+" "+text+" PRIMARY KEY, "+s.identifier("name")+" "+text+" NOT NULL DEFAULT '', "+s.identifier("kind")+" "+text+" NOT NULL DEFAULT 'identity_schema', "+s.identifier("checksum")+" "+text+" NOT NULL DEFAULT '', "+s.identifier("dirty")+" BOOLEAN NOT NULL DEFAULT FALSE, "+s.identifier("applied_at")+" "+text+" NOT NULL, "+s.identifier("service_version")+" "+text+" NOT NULL DEFAULT '', "+s.identifier("duration_ms")+" BIGINT NOT NULL DEFAULT 0, "+s.identifier("operator")+" "+text+" NOT NULL DEFAULT '', "+s.identifier("instance_id")+" "+text+" NOT NULL DEFAULT '', "+s.identifier("backup_id")+" "+text+" NOT NULL DEFAULT '')"); err != nil {
		return false, fmt.Errorf("prepare Identity schema migration ledger: %w", err)
	}
	columns := []struct{ name, definition string }{{"name", text + " NOT NULL DEFAULT ''"}, {"kind", text + " NOT NULL DEFAULT 'identity_schema'"}, {"checksum", text + " NOT NULL DEFAULT ''"}, {"dirty", "BOOLEAN NOT NULL DEFAULT FALSE"}, {"service_version", text + " NOT NULL DEFAULT ''"}, {"duration_ms", "BIGINT NOT NULL DEFAULT 0"}, {"operator", text + " NOT NULL DEFAULT ''"}, {"instance_id", text + " NOT NULL DEFAULT ''"}, {"backup_id", text + " NOT NULL DEFAULT ''"}}
	for _, column := range columns {
		rows, queryErr := db.QueryContext(ctx, "SELECT "+s.identifier(column.name)+" FROM "+s.tableIdentifier(identitySchemaMigrationTable)+" WHERE 1 = 0")
		if queryErr == nil {
			_ = rows.Close()
			continue
		}
		if _, alterErr := db.ExecContext(ctx, "ALTER TABLE "+s.tableIdentifier(identitySchemaMigrationTable)+" ADD COLUMN "+s.identifier(column.name)+" "+column.definition); alterErr != nil {
			return false, alterErr
		}
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.tableIdentifier(identitySchemaMigrationTable)+" WHERE "+s.identifier("version")+" = "+s.placeholder(1), version).Scan(&count); err != nil {
		return false, fmt.Errorf("check Identity schema migration: %w", err)
	}
	if count == 0 {
		return true, nil
	}
	var checksum string
	var dirty bool
	if err := db.QueryRowContext(ctx, "SELECT "+s.identifier("checksum")+", "+s.identifier("dirty")+" FROM "+s.tableIdentifier(identitySchemaMigrationTable)+" WHERE "+s.identifier("version")+" = "+s.placeholder(1), version).Scan(&checksum, &dirty); err != nil {
		return false, err
	}
	if dirty {
		return false, fmt.Errorf("migration.dirty: Identity schema %s", version)
	}
	if strings.TrimSpace(checksum) == "" {
		_, err := db.ExecContext(ctx, "UPDATE "+s.tableIdentifier(identitySchemaMigrationTable)+" SET "+s.identifier("checksum")+" = "+s.placeholder(1)+" WHERE "+s.identifier("version")+" = "+s.placeholder(2), currentIdentitySchemaChecksum(), version)
		return false, err
	}
	if checksum != currentIdentitySchemaChecksum() {
		return false, fmt.Errorf("migration.checksum_drift: Identity schema %s", version)
	}
	return false, nil
}

func (s *IdentityStore) startIdentitySchemaMigration(ctx context.Context, version string) error {
	columns := []string{"version", "name", "kind", "checksum", "dirty", "applied_at", "service_version", "duration_ms", "operator", "instance_id", "backup_id"}
	query := "INSERT INTO " + s.tableIdentifier(identitySchemaMigrationTable) + " (" + strings.Join(quotedColumns(s, columns), ", ") + ") VALUES (" + strings.Join(placeholders(s, len(columns)), ", ") + ")"
	_, err := s.schemaDatabase().ExecContext(ctx, query, version, identitySchemaMigrationName, identitySchemaMigrationKind, currentIdentitySchemaChecksum(), true, time.Now().UTC().Format(time.RFC3339), s.config.ServiceVersion, 0, migrationcontract.Operator(s.config), migrationcontract.InstanceID(s.config), s.migrationBackupID)
	return err
}

func (s *IdentityStore) recordIdentitySchemaMigration(ctx context.Context, version string, duration time.Duration) error {
	_, err := s.schemaDatabase().ExecContext(ctx, "UPDATE "+s.tableIdentifier(identitySchemaMigrationTable)+" SET "+s.identifier("dirty")+" = FALSE, "+s.identifier("duration_ms")+" = "+s.placeholder(1)+", "+s.identifier("applied_at")+" = "+s.placeholder(2)+" WHERE "+s.identifier("version")+" = "+s.placeholder(3), duration.Milliseconds(), time.Now().UTC().Format(time.RFC3339), version)
	if err != nil {
		return fmt.Errorf("record Identity schema migration: %w", err)
	}
	return nil
}

func currentIdentitySchemaChecksum() string {
	sum := sha256.Sum256([]byte(CurrentIdentitySchemaVersion + ":metadata,identity,audit,authentication,authorization_catalog,workspace_provider_credential_identity,portability_receipts,workspace_write_fences,workspace_write_fence_events,managed_identity_database,no_frontend_capability_registry"))
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
