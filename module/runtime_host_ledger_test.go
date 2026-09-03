package module_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodule "github.com/domainry/domainry-identity/module"
)

func TestFactoryUsesRuntimeHostMigrationLedgerWithoutServiceVersionColumn(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "project.db")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(t.Context(), `
		CREATE TABLE _schema_migrations (
			path TEXT PRIMARY KEY,
			version TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL DEFAULT 'schema',
			checksum TEXT NOT NULL DEFAULT '',
			dirty BOOLEAN NOT NULL DEFAULT FALSE,
			applied_at TEXT NOT NULL,
			runtime_version TEXT NOT NULL DEFAULT '',
			duration_ms BIGINT NOT NULL DEFAULT 0,
			operator TEXT NOT NULL DEFAULT '',
			instance_id TEXT NOT NULL DEFAULT '',
			backup_id TEXT NOT NULL DEFAULT ''
		)`); err != nil {
		t.Fatal(err)
	}
	registrar := &testEmbeddedMigrationRegistrar{}
	binding, err := identitymodule.NewFactory(identitymodule.Options{DatabaseDriver: "sqlite", DatabasePath: databasePath}).OpenWithDatabase(
		t.Context(),
		identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "crm"},
		identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: databasePath, Migrations: registrar},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := binding.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	var runtimeVersionColumns, serviceVersionColumns int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pragma_table_info('_schema_migrations') WHERE name = 'runtime_version'`).Scan(&runtimeVersionColumns); err != nil || runtimeVersionColumns != 1 {
		t.Fatalf("Runtime host ledger runtime_version columns=%d err=%v", runtimeVersionColumns, err)
	}
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pragma_table_info('_schema_migrations') WHERE name = 'service_version'`).Scan(&serviceVersionColumns); err != nil || serviceVersionColumns != 0 {
		t.Fatalf("Identity changed Runtime host ledger service_version columns=%d err=%v", serviceVersionColumns, err)
	}
	var embeddedModuleMigrations int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _schema_migrations WHERE kind LIKE 'module:%' AND dirty = FALSE`).Scan(&embeddedModuleMigrations); err != nil || embeddedModuleMigrations == 0 {
		t.Fatalf("embedded module migrations=%d err=%v", embeddedModuleMigrations, err)
	}
}
