package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"time"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	shareddefinition "github.com/domainry/domainry-foundation/definition"
	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/secrets"
	"github.com/domainry/domainry-foundation/telemetry"
	identitymodulehost "github.com/domainry/domainry-identity-sdk/modulehost"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/base"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/connection"
	migrationowner "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/observability"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/workspace"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/platform/config"
	metadatasdk "github.com/domainry/domainry-metadata-sdk"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

// IdentityStore owns a standalone connection or borrows a project-owned pool.
type IdentityStore struct {
	*base.SQLDatabase
	*workspace.WriteFenceStore
	*migrationowner.Coordinator
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
	borrowedDatabase     bool
	relationPrefix       string
	metadataBinding      metadatasdk.Binding
	auditBinding         auditsdk.Binding
	definitionStore      shareddefinition.Store
	hostModuleMigrations identitymodulehost.MigrationRegistrar
}

func (s *IdentityStore) Metadata() metadatasdk.Binding {
	if s == nil {
		return nil
	}
	return s.metadataBinding
}

func (s *IdentityStore) Audit() auditsdk.Binding {
	if s == nil {
		return nil
	}
	return s.auditBinding
}

// BindAudit installs the process-local Audit binding opened by the outer
// composition root. Persistence code receives only the SDK capability and
// never imports or constructs the Audit implementation.
func (s *IdentityStore) BindAudit(binding auditsdk.Binding) error {
	if s == nil || binding == nil || binding.PreparedAppender() == nil {
		return fmt.Errorf("Audit module binding is required")
	}
	s.auditBinding = binding
	s.WriteFenceStore.BindAuditPreparedAppender(binding.PreparedAppender())
	return nil
}

func (s *IdentityStore) Definitions() shareddefinition.StorePort {
	if s == nil {
		return nil
	}
	return s.definitionStore
}

func newMigrationCoordinator(queryDatabase, migrationPool *sql.DB, migrationDatabase driver.SchemaDatabase, backupDatabase, lockDatabase *sql.DB, engine databaseEngine, renderer ormdialect.Renderer, databaseSchema, relationPrefix string, cfg config.Config, secretMaterialKey [32]byte, metrics *observability.Metrics) *migrationowner.Coordinator {
	managementDatabase := queryDatabase
	if migrationPool != nil {
		managementDatabase = migrationPool
	}
	statusReader := migrationowner.NewStatusReader(migrationDatabase, engine, renderer, cfg)
	backupManager := migrationowner.NewBackupManager(migrationowner.BackupOptions{Database: backupDatabase, Engine: engine, Renderer: renderer, DatabaseSchema: databaseSchema, RelationPrefix: relationPrefix, SecretMaterialKey: secretMaterialKey, Metrics: metrics})
	lockManager := migrationowner.NewLockManager(lockDatabase, engine, renderer, databaseSchema, cfg, metrics)
	ledger := migrationowner.NewLedger(migrationDatabase, engine, renderer, databaseSchema)
	pathResolver := migrationowner.NewPathResolver(engine, nil)
	return migrationowner.NewCoordinator(migrationowner.CoordinatorOptions{
		QueryDatabase: queryDatabase, ManagementDatabase: managementDatabase,
		Engine: engine, Renderer: renderer, DatabaseSchema: databaseSchema, Config: cfg,
		StatusReader: statusReader, BackupManager: backupManager, LockManager: lockManager,
		Ledger: ledger, PathResolver: pathResolver,
	})
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
	if err := engine.Configure(ctx, db, cfg); err != nil {
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
	coordinator := newMigrationCoordinator(db, migrationDB, migrationDatabase, backupDatabase, lockDatabase, engine, sqlDatabase.SQLRenderer, databaseSchema, "", cfg, activeMaterial, operationalMetrics)
	store := &IdentityStore{SQLDatabase: sqlDatabase, WriteFenceStore: workspace.NewWriteFenceStore(db, sqlDatabase.SQLRenderer), Coordinator: coordinator, db: db, migrationDB: migrationDB, engine: engine, config: cfg, databaseSchema: databaseSchema, postgresProfile: connectionState.PostgresProfile, postgresCapabilities: connectionState.PostgresCapabilities, migratorCapabilities: connectionState.MigratorCapabilities, secretMaterialKey: activeMaterial, secretKeyProvider: keyRing, idempotencyMetrics: idempotency.NewMemoryMetricsCollector(4096), sqlMetrics: sqlMetrics, operationalMetrics: operationalMetrics}
	store.definitionStore = shareddefinition.NewStore(db, sqlDatabase.SQLRenderer, "domainry-identity")
	var migrationErr error
	migrationStarted := time.Now()
	if cfg.EffectiveDatabaseMigrationMode() == "verify" {
		migrationErr = store.Coordinator.Verify(ctx, cfg)
	} else {
		migrationErr = store.Coordinator.Apply(ctx, cfg)
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
	sqlDatabase := base.NewSQLDatabase(db, engine, schema, "")
	operationalMetrics := observability.NewMetrics(cfg.MigrationBackupLastSuccessAt, cfg.MigrationRestoreDrillSuccessAt)
	coordinator := newMigrationCoordinator(db, nil, db, db, db, engine, sqlDatabase.SQLRenderer, schema, "", cfg, activeMaterial, operationalMetrics)
	store := &IdentityStore{
		SQLDatabase: sqlDatabase, WriteFenceStore: workspace.NewWriteFenceStore(db, sqlDatabase.SQLRenderer),
		Coordinator: coordinator,
		db:          db, engine: engine, config: cfg, databaseSchema: schema,
		secretMaterialKey: activeMaterial, secretKeyProvider: keyRing,
		idempotencyMetrics: idempotency.NewMemoryMetricsCollector(4096),
		sqlMetrics:         telemetry.NewSQLMetrics(), operationalMetrics: operationalMetrics,
		borrowedDatabase: true,
		relationPrefix:   "",
	}
	store.definitionStore = shareddefinition.NewStore(db, sqlDatabase.SQLRenderer, "domainry-identity")
	// A borrowed database is migrated exclusively by the embedding host. The
	// module factory submits source-owned schema work through the host registrar
	// after this connection-only store is prepared.
	store.migrationCompatible = true
	return store, nil
}

func identityDataKeyProvider(cfg config.Config, factory func(secrets.Key, ...secrets.Key) (secrets.KeyProvider, error)) ([32]byte, secrets.KeyProvider, error) {
	activeMaterial := sha256.Sum256([]byte(cfg.IdentityDataSecretKey))
	activeID := strings.TrimSpace(cfg.IdentityDataActiveKeyID)
	if activeID == "" {
		activeID = "dev-v1"
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
	if s.Coordinator != nil && s.LockManager != nil {
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
	if s == nil {
		return postgres.SafeStatus{}, false
	}
	return databaseHealthFor(s.engine).Status(s)
}

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
}

func (s *IdentityStore) DatabaseReadiness() DatabaseReadiness {
	if s == nil {
		return DatabaseReadiness{}
	}
	return databaseHealthFor(s.engine).Readiness(s)
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
