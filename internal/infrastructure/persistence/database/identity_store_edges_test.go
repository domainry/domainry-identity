package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/secrets"
	"github.com/domainry/domainry-identity/internal/platform/config"
	_ "modernc.org/sqlite"
)

func TestIdentityStoreNilAndDialectContracts(t *testing.T) {
	var nilStore *IdentityStore
	if err := nilStore.Close(); err != nil {
		t.Fatalf("nil close: %v", err)
	}
	if err := nilStore.CloseContext(t.Context()); err != nil {
		t.Fatalf("nil context close: %v", err)
	}
	if nilStore.SQLMetrics() != nil || nilStore.OperationalMetrics() != nil || nilStore.IdempotencyMetrics(t.Context()) != nil {
		t.Fatal("nil store exposed metrics")
	}
	if _, ok := nilStore.DatabaseStatus(); ok {
		t.Fatal("nil store exposed database status")
	}
	if readiness := nilStore.DatabaseReadiness(); readiness.Ready || readiness.ReadReady || readiness.WriteReady || readiness.MigrationCompatible {
		t.Fatalf("nil readiness = %#v", readiness)
	}

	store := &IdentityStore{}
	if readiness := store.DatabaseReadiness(); readiness.Ready || readiness.ReadReady {
		t.Fatalf("empty readiness = %#v", readiness)
	}
	if got := SQLIdentifier("safe_name"); got != `"safe_name"` || !validSQLIdentifier("safe_name") || validSQLIdentifier("unsafe-name") {
		t.Fatalf("identifier=%q valid=%v unsafe=%v", got, validSQLIdentifier("safe_name"), validSQLIdentifier("unsafe-name"))
	}
	if err := store.SetEngineForTesting("mysql"); err != nil || store.metadataIDColumnType() != "VARCHAR(191)" {
		t.Fatalf("mysql dialect type=%q error=%v", store.metadataIDColumnType(), err)
	}
	if err := store.SetEngineForTesting("postgres"); err != nil || store.metadataIDColumnType() != "TEXT" {
		t.Fatalf("postgres dialect type=%q error=%v", store.metadataIDColumnType(), err)
	}
	if err := store.SetEngineForTesting("oracle"); err == nil {
		t.Fatal("unsupported dialect accepted")
	}
}

func TestIdentityStoreOpenContextAndKeyProviderEdges(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := OpenContext(canceled, config.Config{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled open = %v", err)
	}
	if _, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "oracle"}); err == nil {
		t.Fatal("unsupported database driver accepted")
	}
	if _, err := OpenContextWithKeyProvider(t.Context(), config.Config{}, nil); err == nil {
		t.Fatal("nil key provider accepted")
	}
	keyRing, err := secrets.NewMemoryKeyRing(secrets.Key{ID: "active", Material: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "runtime.db"), IdentityDataSecretKey: "runtime-key"}
	store, err := OpenContextWithKeyProvider(t.Context(), cfg, keyRing)
	if err != nil {
		t.Fatal(err)
	}
	if store.secretKeyProvider != keyRing || store.SQLMetrics() == nil || store.OperationalMetrics() == nil || store.IdempotencyMetrics(t.Context()) == nil {
		t.Fatal("store dependencies were not initialized")
	}
	if status, ok := store.DatabaseStatus(); ok {
		t.Fatalf("sqlite status=%#v ok=%v", status, ok)
	}
	if readiness := store.DatabaseReadiness(); !readiness.Ready || !readiness.ReadReady || !readiness.WriteReady || !readiness.MigrationCompatible {
		t.Fatalf("sqlite readiness = %#v", readiness)
	}
	if err := store.CloseContext(t.Context()); err != nil {
		t.Fatalf("close context: %v", err)
	}
}

func TestOpenBorrowedContextUsesHostDialectWithoutRelationPrefix(t *testing.T) {
	for _, test := range []struct {
		driver      string
		placeholder string
	}{
		{driver: "sqlite", placeholder: "?"},
		{driver: "mysql", placeholder: "?"},
		{driver: "postgres", placeholder: "$1"},
	} {
		t.Run(test.driver, func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			store, err := OpenBorrowedContext(t.Context(), config.Config{
				DatabaseDriver: test.driver,
				DatabaseSchema: "host_schema",
			}, db)
			if err != nil {
				t.Fatal(err)
			}
			if !store.borrowedDatabase || store.RelationPrefix() != "" {
				t.Fatalf("borrowed=%t relation prefix=%q", store.borrowedDatabase, store.RelationPrefix())
			}
			renderer := store.BuilderRenderer()
			if table := renderer.Table("_identity_users"); strings.Contains(table, "domainry_identity_") || !strings.Contains(table, "_identity_users") {
				t.Fatalf("borrowed %s table=%q", test.driver, table)
			}
			if placeholder := renderer.Placeholder(1); placeholder != test.placeholder {
				t.Fatalf("borrowed %s placeholder=%q want=%q", test.driver, placeholder, test.placeholder)
			}
			if store.Coordinator == nil || store.Coordinator.Ledger == nil {
				t.Fatal("borrowed store has no host-ledger adapter")
			}
			ledgerDDL := store.Coordinator.Ledger.SchemaSQL()
			if strings.Contains(ledgerDDL, "domainry_identity_") || !strings.Contains(ledgerDDL, "_schema_migrations") {
				t.Fatalf("borrowed %s ledger DDL=%q", test.driver, ledgerDDL)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if err := db.PingContext(t.Context()); err != nil {
				t.Fatalf("borrowed pool was closed: %v", err)
			}
		})
	}
}

func TestIdentityStoreSystemUpdateContract(t *testing.T) {
	cfg := config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "updates.db"), IdentityDataSecretKey: "runtime-key"}
	store, err := OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.DB().ExecContext(t.Context(), `CREATE TABLE "edge_updates" ("id" TEXT PRIMARY KEY, "name" TEXT, "status" TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := store.insertSystemRowContext(t.Context(), "edge_updates", []string{"id", "name", "status"}, []any{"one", "before", "draft"}); err != nil {
		t.Fatal(err)
	}
	if err := store.updateSystemRowContext(t.Context(), "edge_updates", "one", []string{"name", "status"}, []any{"after", "active"}); err != nil {
		t.Fatal(err)
	}
	var name, status string
	if err := store.DB().QueryRowContext(t.Context(), `SELECT name, status FROM edge_updates WHERE id = 'one'`).Scan(&name, &status); err != nil || name != "after" || status != "active" {
		t.Fatalf("name=%q status=%q error=%v", name, status, err)
	}
	if err := store.updateSystemRowContext(t.Context(), "missing_table", "one", []string{"name"}, []any{"after"}); err == nil || !strings.Contains(err.Error(), "update missing_table") {
		t.Fatalf("missing update error = %v", err)
	}
}
