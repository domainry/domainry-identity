package schema

import (
	"database/sql"
	"path/filepath"
	"testing"

	ormschema "github.com/domainry/domainry-orm/schema"
	_ "modernc.org/sqlite"
)

func TestWorkspaceBootstrapRolePolicyMigrationAddsEvidenceColumns(t *testing.T) {
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "bootstrap-role-policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := scriptedSchemaStore{db: database, driver: "sqlite"}
	statement, arguments, err := ormschema.NewTable(store.SchemaRenderer(), "_identity_workspace_bootstrap_receipts").
		Columns(ormschema.Column("id", ormschema.TextKey(191)).NotNull()).PrimaryKey("id").Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), statement, arguments...); err != nil {
		t.Fatal(err)
	}
	if err := ensureWorkspaceBootstrapRolePolicyEvidence(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	columns, err := store.TableColumns(t.Context(), "_identity_workspace_bootstrap_receipts")
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"role_catalog_sha256", "navigation_catalog_sha256", "initial_workspace_administrator_role_key"} {
		if !columns[column] {
			t.Fatalf("migration omitted %s: %#v", column, columns)
		}
	}
	if err := ensureWorkspaceBootstrapRolePolicyEvidence(t.Context(), store); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}
}
