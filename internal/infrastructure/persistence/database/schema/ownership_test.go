package schema_test

import (
	"path/filepath"
	"sort"
	"testing"

	auditmodule "github.com/domainry/domainry-audit/module"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestEveryStandaloneIdentityTableHasOneOwnerAndMigrationDisposition(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite",
		DBPath:         filepath.Join(t.TempDir(), "identity.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}

	ownership := map[string]identityschema.TableOwnership{}
	moduleOwned := map[string]bool{}
	for _, table := range auditmodule.OwnedTables() {
		moduleOwned[table] = true
	}
	for _, table := range identityschema.IdentityTableOwnership() {
		if table.Name == "" || table.Boundary == "" || table.MigrationDisposition == "" {
			t.Errorf("incomplete table ownership: %+v", table)
		}
		if _, duplicate := ownership[table.Name]; duplicate {
			t.Errorf("duplicate table ownership for %q", table.Name)
		}
		ownership[table.Name] = table
		if table.ContainsSecret && table.MigrationDisposition == identityschema.MigrationPortable {
			t.Errorf("secret-bearing table %q cannot be portable", table.Name)
		}
	}

	rows, err := store.DB().QueryContext(t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	actual := []string{}
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		actual = append(actual, table)
		if _, declared := ownership[table]; !declared && !moduleOwned[table] {
			t.Errorf("standalone Identity table %q has no ownership classification", table)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !sort.StringsAreSorted(actual) {
		t.Fatalf("table inventory is not deterministic: %v", actual)
	}
}

func TestIdentityOwnershipCatalogRejectsPlaneBusinessTables(t *testing.T) {
	for _, table := range identityschema.IdentityTableOwnership() {
		for _, prefix := range []string{"record_", "workflow_", "automation_", "notification_", "party_", "integration_"} {
			if len(table.Name) >= len(prefix) && table.Name[:len(prefix)] == prefix {
				t.Errorf("Plane-owned table %q leaked into Identity ownership catalog", table.Name)
			}
		}
	}
}
