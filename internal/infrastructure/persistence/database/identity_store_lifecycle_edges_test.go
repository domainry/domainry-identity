package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/secrets"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/workspace"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityStoreCloseErrorsAndMigrationConnection(t *testing.T) {
	if err := (&IdentityStore{}).Close(); err != nil {
		t.Fatalf("empty close=%v", err)
	}
	primaryState := &databaseSQLState{closeErr: errors.New("primary close")}
	migrationState := &databaseSQLState{closeErr: errors.New("migration close")}
	primary, migration := openDatabaseScriptedDB(primaryState), openDatabaseScriptedDB(migrationState)
	_ = primary.PingContext(t.Context())
	_ = migration.PingContext(t.Context())
	store := &IdentityStore{db: primary, migrationDB: migration}
	if err := store.Close(); err == nil || !errors.Is(err, migrationState.closeErr) {
		t.Fatalf("close error=%v", err)
	}

	db := openDatabaseScriptedDB(&databaseSQLState{})
	connection, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	store = &IdentityStore{db: db, migrationConn: connection}
	if err := store.Close(); err != nil || store.migrationConn != nil {
		t.Fatalf("connection close=%v", err)
	}

	primary = openDatabaseScriptedDB(&databaseSQLState{closeErr: errors.New("primary close")})
	_ = primary.PingContext(t.Context())
	store = &IdentityStore{db: primary}
	if err := store.Close(); err == nil {
		t.Fatal("primary close error was ignored")
	}
}

func TestIdentityStoreCloseContextTimeoutAndError(t *testing.T) {
	state := &databaseSQLState{closeErr: errDatabaseSQL}
	store := &IdentityStore{db: openDatabaseScriptedDB(state)}
	_ = store.db.PingContext(t.Context())
	if err := store.CloseContext(t.Context()); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("close error=%v", err)
	}

	state = &databaseSQLState{closeStarted: make(chan struct{}), closeBlock: make(chan struct{})}
	store = &IdentityStore{db: openDatabaseScriptedDB(state)}
	_ = store.db.PingContext(t.Context())
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-state.closeStarted
		cancel()
	}()
	if err := store.CloseContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("timeout error=%v", err)
	}
	close(state.closeBlock)
}

func TestIdentityStoreReadinessFailurePriority(t *testing.T) {
	profile := postgres.ConnectionProfile{TLS: true, MigrationConfigured: true, RLSEnabled: true}
	tests := []struct {
		name       string
		capability postgres.Capabilities
		migrator   postgres.Capabilities
		compatible bool
		rls        WorkspaceRLSStatus
		failure    string
	}{
		{"schema usage", postgres.Capabilities{SchemaExists: true}, postgres.Capabilities{Database: "runtime"}, true, WorkspaceRLSStatus{Enabled: true}, postgres.FailureSchemaIncompatible},
		{"tls", postgres.Capabilities{SchemaExists: true, SchemaUsage: true}, postgres.Capabilities{Database: "runtime"}, true, WorkspaceRLSStatus{Enabled: true}, postgres.FailureTLS},
		{"migration connection", postgres.Capabilities{SchemaExists: true, SchemaUsage: true, TLS: true}, postgres.Capabilities{}, true, WorkspaceRLSStatus{Enabled: true}, postgres.FailureServerUnavailable},
		{"migration incompatible", postgres.Capabilities{SchemaExists: true, SchemaUsage: true, TLS: true}, postgres.Capabilities{Database: "runtime"}, false, WorkspaceRLSStatus{Enabled: true}, "migration_incompatible"},
		{"rls disabled", postgres.Capabilities{SchemaExists: true, SchemaUsage: true, TLS: true}, postgres.Capabilities{Database: "runtime"}, true, WorkspaceRLSStatus{}, "rls_incompatible"},
		{"rls missing", postgres.Capabilities{SchemaExists: true, SchemaUsage: true, TLS: true}, postgres.Capabilities{Database: "runtime"}, true, WorkspaceRLSStatus{Enabled: true, MissingTables: []string{"records"}}, "rls_incompatible"},
		{"ready rls", postgres.Capabilities{SchemaExists: true, SchemaUsage: true, TLS: true}, postgres.Capabilities{Database: "runtime"}, true, WorkspaceRLSStatus{Enabled: true}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &IdentityStore{db: openReadinessTestDatabase(t), postgresProfile: &profile, postgresCapabilities: test.capability, migratorCapabilities: test.migrator, migrationCompatible: test.compatible, RLSManager: workspace.NewRLSManager(workspace.RLSOptions{Status: test.rls})}
			if readiness := store.DatabaseReadiness(); readiness.Failure != test.failure || readiness.Ready != (test.failure == "") {
				t.Fatalf("readiness=%#v", readiness)
			}
		})
	}
}

func TestIdentityStoreIdempotencyObservationAndProviderOpenError(t *testing.T) {
	var nilStore *IdentityStore
	nilStore.ObserveIdempotency(t.Context(), "workspace", "scope", idempotency.OutcomeAcquired)
	(&IdentityStore{}).ObserveIdempotency(t.Context(), "workspace", "scope", idempotency.OutcomeAcquired)
	store := &IdentityStore{idempotencyMetrics: idempotency.NewMemoryMetricsCollector(10)}
	store.ObserveIdempotency(t.Context(), "workspace", "scope", idempotency.OutcomeAcquired)
	if store.IdempotencyMetrics(t.Context()) == nil {
		t.Fatal("metrics missing")
	}
	provider, err := secrets.NewMemoryKeyRing(secrets.Key{ID: "key", Material: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenContextWithKeyProvider(t.Context(), config.Config{DatabaseDriver: "invalid"}, provider); err == nil {
		t.Fatal("open error was ignored")
	}
}

func TestIdentityStoreCloseContextMigrationDatabaseError(t *testing.T) {
	migration := openDatabaseScriptedDB(&databaseSQLState{closeErr: errDatabaseSQL})
	_ = migration.PingContext(t.Context())
	store := &IdentityStore{migrationDB: migration}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := store.CloseContext(ctx); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("error=%v", err)
	}
	migration = openDatabaseScriptedDB(&databaseSQLState{closeErr: errDatabaseSQL})
	primary := openDatabaseScriptedDB(&databaseSQLState{})
	_ = migration.PingContext(t.Context())
	_ = primary.PingContext(t.Context())
	store = &IdentityStore{migrationDB: migration, db: primary}
	if err := store.CloseContext(ctx); !errors.Is(err, errDatabaseSQL) {
		t.Fatalf("dual close error=%v", err)
	}
}
