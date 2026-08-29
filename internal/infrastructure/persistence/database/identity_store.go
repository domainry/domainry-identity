package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/secrets"
	"github.com/domainry/domainry-foundation/telemetry"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/base"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/connection"
	migrationowner "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/observability"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/workspace"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

// IdentityStore owns a standalone connection or borrows a project-owned pool.
type IdentityStore struct {
	*base.SQLDatabase
	*workspace.WriteFenceStore
	*workspace.RLSManager
	*workspace.ScopeValidator
	*migrationowner.StatusReader
	*migrationowner.BackupManager
	*migrationowner.LockManager
	db                   *sql.DB
	migrationDB          *sql.DB
	engine               databaseEngine
	config               config.Config
	databaseSchema       string
	postgresProfile      *postgres.ConnectionProfile
	postgresCapabilities postgres.Capabilities
	migratorCapabilities postgres.Capabilities
	secretMaterialKey    [32]byte
	secretKeyProvider    secrets.KeyProvider
	migrationCompatible  bool
	idempotencyMetrics   *idempotency.MemoryMetricsCollector
	sqlMetrics           *telemetry.SQLMetrics
	operationalMetrics   *observability.Metrics
	schemaAssembler      identitySchemaAssembler
	migrationReadDir     func(string) ([]os.DirEntry, error)
	borrowedDatabase     bool
	relationPrefix       string
}

func OpenContext(ctx context.Context, cfg config.Config) (*IdentityStore, error) {
	return openContextWithDependencies(ctx, cfg, defaultIdentityOpenDependencies())
}

func openContextWithDependencies(ctx context.Context, cfg config.Config, dependencies identityOpenDependencies) (*IdentityStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	engine, err := dependencies.engine(cfg.DatabaseDriver)
	if err != nil {
		return nil, err
	}
	sqlMetrics := telemetry.NewSQLMetrics()
	operationalMetrics := observability.NewMetrics(cfg.MigrationBackupLastSuccessAt, cfg.MigrationRestoreDrillSuccessAt)
	connectionState, err := connection.Open(ctx, cfg, engine, dependencies.connection, sqlMetrics)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db, migrationDB := connectionState.Database, connectionState.MigrationDatabase
	if err := engine.Configure(ctx, db, connectionState.DSN); err != nil {
		if migrationDB != nil {
			_ = migrationDB.Close()
		}
		_ = db.Close()
		return nil, err
	}
	activeMaterial, keyRing, err := identityDataKeyProvider(cfg, dependencies.keyRing)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize Identity data key ring: %w", err)
	}
	databaseSchema := connectionState.DatabaseSchema
	sqlDatabase := base.NewSQLDatabase(db, engine, databaseSchema, "")
	rlsManager := workspace.NewRLSManager(workspace.RLSOptions{Database: db, MigrationDatabase: migrationDB, Engine: engine, Renderer: sqlDatabase.SQLRenderer, DatabaseSchema: databaseSchema, ApplicationRole: connectionState.PostgresCapabilities.User, Enabled: cfg.DatabaseRLSEnabled, Apply: cfg.EffectiveDatabaseMigrationMode() == "apply", ConnectionProfileSet: connectionState.PostgresProfile != nil})
	migrationDatabase := driver.SchemaDatabase(db)
	backupDatabase := db
	if migrationDB != nil {
		migrationDatabase = migrationDB
		backupDatabase = migrationDB
	}
	lockDatabase := db
	if migrationDB != nil {
		lockDatabase = migrationDB
	}
	store := &IdentityStore{SQLDatabase: sqlDatabase, WriteFenceStore: workspace.NewWriteFenceStore(db, sqlDatabase.SQLRenderer), RLSManager: rlsManager, ScopeValidator: workspace.NewScopeValidator(db, engine, sqlDatabase.SQLRenderer, databaseSchema, ""), StatusReader: migrationowner.NewStatusReader(migrationDatabase, engine, sqlDatabase.SQLRenderer, cfg), BackupManager: migrationowner.NewBackupManager(migrationowner.BackupOptions{Database: backupDatabase, Engine: engine, Renderer: sqlDatabase.SQLRenderer, DatabaseSchema: databaseSchema, SecretMaterialKey: activeMaterial, Metrics: operationalMetrics}), LockManager: migrationowner.NewLockManager(lockDatabase, engine, sqlDatabase.SQLRenderer, databaseSchema, cfg, operationalMetrics), db: db, migrationDB: migrationDB, engine: engine, config: cfg, databaseSchema: databaseSchema, postgresProfile: connectionState.PostgresProfile, postgresCapabilities: connectionState.PostgresCapabilities, migratorCapabilities: connectionState.MigratorCapabilities, secretMaterialKey: activeMaterial, secretKeyProvider: keyRing, idempotencyMetrics: idempotency.NewMemoryMetricsCollector(4096), sqlMetrics: sqlMetrics, operationalMetrics: operationalMetrics}
	var migrationErr error
	migrationStarted := time.Now()
	if cfg.EffectiveDatabaseMigrationMode() == "verify" {
		migrationErr = store.verifyMigrations(ctx, cfg)
	} else {
		migrationErr = store.applyMigrations(ctx, cfg)
	}
	operationalMetrics.ObserveMigration(time.Since(migrationStarted), migrationErr)
	if migrationErr != nil {
		if migrationDB != nil {
			_ = migrationDB.Close()
		}
		_ = db.Close()
		return nil, migrationErr
	}
	store.migrationCompatible = true
	return store, nil
}

// OpenBorrowedContext prepares an Identity store on a project-owned pool. The
// caller retains lifecycle ownership of db; Close and CloseContext never close
// a borrowed pool.
func OpenBorrowedContext(ctx context.Context, cfg config.Config, db *sql.DB) (*IdentityStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if db == nil {
		return nil, fmt.Errorf("borrowed database pool is required")
	}
	engine, err := connection.EngineFor(cfg.DatabaseDriver)
	if err != nil {
		return nil, err
	}
	activeMaterial, keyRing, err := identityDataKeyProvider(cfg, defaultIdentityOpenDependencies().keyRing)
	if err != nil {
		return nil, fmt.Errorf("initialize Identity data key ring: %w", err)
	}
	schema := engine.DatabaseSchema(cfg)
	sqlDatabase := base.NewSQLDatabase(db, engine, schema, "domainry_identity_")
	operationalMetrics := observability.NewMetrics(cfg.MigrationBackupLastSuccessAt, cfg.MigrationRestoreDrillSuccessAt)
	store := &IdentityStore{
		SQLDatabase: sqlDatabase, WriteFenceStore: workspace.NewWriteFenceStore(db, sqlDatabase.SQLRenderer),
		RLSManager:     workspace.NewRLSManager(workspace.RLSOptions{Database: db, Engine: engine, Renderer: sqlDatabase.SQLRenderer, DatabaseSchema: schema, Enabled: cfg.DatabaseRLSEnabled, Apply: cfg.EffectiveDatabaseMigrationMode() == "apply"}),
		ScopeValidator: workspace.NewScopeValidator(db, engine, sqlDatabase.SQLRenderer, schema, "domainry_identity_"),
		StatusReader:   migrationowner.NewStatusReader(db, engine, sqlDatabase.SQLRenderer, cfg),
		BackupManager:  migrationowner.NewBackupManager(migrationowner.BackupOptions{Database: db, Engine: engine, Renderer: sqlDatabase.SQLRenderer, DatabaseSchema: schema, RelationPrefix: "domainry_identity_", SecretMaterialKey: activeMaterial, Metrics: operationalMetrics}),
		LockManager:    migrationowner.NewLockManager(db, engine, sqlDatabase.SQLRenderer, schema, cfg, operationalMetrics),
		db:             db, engine: engine, config: cfg, databaseSchema: schema,
		secretMaterialKey: activeMaterial, secretKeyProvider: keyRing,
		idempotencyMetrics: idempotency.NewMemoryMetricsCollector(4096),
		sqlMetrics:         telemetry.NewSQLMetrics(), operationalMetrics: operationalMetrics,
		borrowedDatabase: true,
		relationPrefix:   "domainry_identity_",
	}
	if cfg.EffectiveDatabaseMigrationMode() == "verify" {
		err = store.verifyMigrations(ctx, cfg)
	} else {
		err = store.applyMigrations(ctx, cfg)
	}
	if err != nil {
		return nil, err
	}
	store.migrationCompatible = true
	return store, nil
}

func identityDataKeyProvider(cfg config.Config, factory func(secrets.Key, ...secrets.Key) (secrets.KeyProvider, error)) ([32]byte, secrets.KeyProvider, error) {
	activeMaterial := sha256.Sum256([]byte(cfg.IdentityDataSecretKey))
	activeID := strings.TrimSpace(cfg.IdentityDataActiveKeyID)
	if activeID == "" {
		activeID = "legacy-v1"
	}
	decryptOnly := make([]secrets.Key, 0, len(cfg.IdentityDataDecryptOnlyKeys))
	for id, value := range cfg.IdentityDataDecryptOnlyKeys {
		material := sha256.Sum256([]byte(value))
		decryptOnly = append(decryptOnly, secrets.Key{ID: id, Material: material[:]})
	}
	keyRing, err := factory(secrets.Key{ID: activeID, Material: activeMaterial[:]}, decryptOnly...)
	return activeMaterial, keyRing, err
}

// OpenContextWithKeyProvider replaces the local env/file key ring with a
// production KMS, Vault, or Secret Manager adapter before secret access.
func OpenContextWithKeyProvider(ctx context.Context, cfg config.Config, provider secrets.KeyProvider) (*IdentityStore, error) {
	if provider == nil {
		return nil, fmt.Errorf("secret key provider is required")
	}
	store, err := OpenContext(ctx, cfg)
	if err != nil {
		return nil, err
	}
	store.secretKeyProvider = provider
	return store, nil
}

func (s *IdentityStore) Close() error {
	if s == nil {
		return nil
	}
	if s.borrowedDatabase {
		return nil
	}
	var first error
	if s.LockManager != nil {
		first = s.LockManager.Close()
	}
	if s.migrationDB != nil {
		first = s.migrationDB.Close()
	}
	if s.db != nil {
		if err := s.db.Close(); first == nil {
			first = err
		}
	}
	return first
}

// CloseContext stops accepting new work and lets database/sql drain operations
// already in flight, bounded by the caller's shutdown deadline.
func (s *IdentityStore) CloseContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.borrowedDatabase {
		return nil
	}
	done := make(chan error, 1)
	go func() {
		var first error
		if s.migrationDB != nil {
			first = s.migrationDB.Close()
		}
		if s.db != nil {
			if err := s.db.Close(); first == nil {
				first = err
			}
		}
		done <- first
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("close Identity database: %w", ctx.Err())
	}
}

func (s *IdentityStore) DB() *sql.DB {
	return s.db
}

func (s *IdentityStore) SQLMetrics() *telemetry.SQLMetrics {
	if s == nil {
		return nil
	}
	return s.sqlMetrics
}

func (s *IdentityStore) OperationalMetrics() *observability.Metrics {
	if s == nil {
		return nil
	}
	return s.operationalMetrics
}

func (s *IdentityStore) PersistenceEngine() driver.Engine {
	return s.engine
}

func (s *IdentityStore) DatabaseSchema() string {
	return s.databaseSchema
}

func (s *IdentityStore) RelationPrefix() string {
	return s.relationPrefix
}

func (s *IdentityStore) DatabaseStatus() (postgres.SafeStatus, bool) {
	if s == nil || s.postgresProfile == nil {
		return postgres.SafeStatus{}, false
	}
	return s.postgresProfile.SafeStatus(), true
}

type WorkspaceRLSStatus = workspace.WorkspaceRLSStatus

const CurrentIdentityWorkspaceRLSPolicyVersion = workspace.CurrentIdentityWorkspaceRLSPolicyVersion

type DatabaseReadiness struct {
	Ready                    bool   `json:"ready"`
	Failure                  string `json:"failure,omitempty"`
	ReadReady                bool   `json:"read_ready"`
	WriteReady               bool   `json:"write_ready"`
	MigrationCompatible      bool   `json:"migration_compatible"`
	PoolDegraded             bool   `json:"pool_degraded"`
	SchemaExists             bool   `json:"schema_exists"`
	SchemaUsage              bool   `json:"schema_usage"`
	ReadOnly                 bool   `json:"read_only"`
	TLSVerified              bool   `json:"tls_verified"`
	MigrationConnectionReady bool   `json:"migration_connection_ready"`
	RLSEnabled               bool   `json:"rls_enabled"`
	RLSPolicyVersion         string `json:"rls_policy_version,omitempty"`
	RLSCoveredTables         int    `json:"rls_covered_tables"`
	RLSMissingTables         int    `json:"rls_missing_tables"`
}

func (s *IdentityStore) DatabaseReadiness() DatabaseReadiness {
	if s == nil || s.postgresProfile == nil {
		ready := s != nil && s.db != nil
		return DatabaseReadiness{Ready: ready, ReadReady: ready, WriteReady: ready, MigrationCompatible: ready}
	}
	capability := s.postgresCapabilities
	stats := s.db.Stats()
	rlsStatus := s.WorkspaceRLSStatus(context.Background())
	result := DatabaseReadiness{
		SchemaExists:             capability.SchemaExists,
		SchemaUsage:              capability.SchemaUsage,
		ReadOnly:                 capability.ReadOnly || capability.InRecovery,
		TLSVerified:              capability.TLS == s.postgresProfile.TLS,
		MigrationConnectionReady: !s.postgresProfile.MigrationConfigured || s.migratorCapabilities.Database != "",
		RLSEnabled:               rlsStatus.Enabled,
		RLSPolicyVersion:         rlsStatus.PolicyVersion,
		RLSCoveredTables:         len(rlsStatus.CoveredTables),
		RLSMissingTables:         len(rlsStatus.MissingTables),
		ReadReady:                capability.SchemaExists && capability.SchemaUsage,
		WriteReady:               capability.SchemaExists && capability.SchemaUsage && !capability.ReadOnly && !capability.InRecovery,
		MigrationCompatible:      s.migrationCompatible,
		PoolDegraded:             stats.MaxOpenConnections > 0 && stats.InUse >= stats.MaxOpenConnections,
	}
	switch {
	case !result.SchemaExists || !result.SchemaUsage:
		result.Failure = postgres.FailureSchemaIncompatible
	case result.ReadOnly:
		result.Failure = "read_only"
	case !result.TLSVerified:
		result.Failure = postgres.FailureTLS
	case !result.MigrationConnectionReady:
		result.Failure = postgres.FailureServerUnavailable
	case !result.MigrationCompatible:
		result.Failure = "migration_incompatible"
	case result.PoolDegraded:
		result.Failure = "pool_degraded"
	case s.postgresProfile.RLSEnabled && (!result.RLSEnabled || result.RLSMissingTables > 0):
		result.Failure = "rls_incompatible"
	default:
		result.Ready = true
	}
	return result
}

func (s *IdentityStore) ObserveIdempotency(_ context.Context, workspaceID, scope string, outcome idempotency.Outcome) {
	if s != nil && s.idempotencyMetrics != nil {
		s.idempotencyMetrics.Observe(workspaceID, scope, outcome)
	}
}

func (s *IdentityStore) IdempotencyMetrics(_ context.Context) idempotency.MetricsCollector {
	if s == nil {
		return nil
	}
	return s.idempotencyMetrics
}
