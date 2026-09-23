package schema_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	auditmodule "github.com/domainry/domainry-audit/module"
	shareddefinition "github.com/domainry/domainry-foundation/definition"
	"github.com/domainry/domainry-foundation/schemaownership"
	sharedsubject "github.com/domainry/domainry-foundation/subjectlifecycle"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/platform/config"
	metadatamodule "github.com/domainry/domainry-metadata/module"
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
	hostOwned := map[string]bool{"_schema_migrations": true}
	for _, table := range identityschema.OperationsKernelTables() {
		hostOwned[table] = true
	}
	for _, table := range auditmodule.OwnedTables() {
		moduleOwned[table] = true
	}
	for _, table := range shareddefinition.OwnedTables() {
		moduleOwned[table] = true
	}
	for _, table := range sharedsubject.OwnedTables() {
		moduleOwned[table] = true
	}
	for _, table := range metadatamodule.OwnedTables() {
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
		if moduleOwned[table.Name] {
			t.Errorf("table %q is claimed by both Identity and an embedded module", table.Name)
		}
		if table.ContainsSecret && table.MigrationDisposition == identityschema.MigrationPortable {
			t.Errorf("secret-bearing table %q cannot be portable", table.Name)
		}
		if table.Boundary == "identity_directory" {
			t.Errorf("table %q retains the retired directory ownership boundary", table.Name)
		}
	}

	// SQLite's schema catalog has no portable domainry-orm equivalent. This
	// dialect-focused regression intentionally inspects the fresh physical schema.
	rows, err := store.DB().QueryContext(t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	actual := []string{}
	actualSet := map[string]bool{}
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		actual = append(actual, table)
		actualSet[table] = true
		for _, retired := range []string{"directory", "surface", "business_workspace", "tenant_admin", "portal"} {
			if strings.Contains(table, retired) {
				t.Errorf("fresh Identity schema retains retired table %q", table)
			}
		}
		if _, declared := ownership[table]; !declared && !moduleOwned[table] && !hostOwned[table] {
			t.Errorf("standalone Identity table %q has no ownership classification", table)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !sort.StringsAreSorted(actual) {
		t.Fatalf("table inventory is not deterministic: %v", actual)
	}
	for _, retired := range []string{"_identity_role_definitions", "_identity_role_definition_versions", "_identity_profile_binding_definitions", "_identity_profile_binding_definition_versions", "_identity_manifest_catalog"} {
		if actualSet[retired] {
			t.Errorf("fresh Identity schema retains retired private Definition table %q", retired)
		}
	}
	for table := range ownership {
		if !actualSet[table] {
			t.Errorf("owned Identity table %q is absent from the fresh schema", table)
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for _, table := range actual {
		// pragma_table_info is SQLite-only and has no portable domainry-orm
		// equivalent; it is required here to reject retired physical columns.
		columnRows, err := store.DB().QueryContext(t.Context(), `SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		for columnRows.Next() {
			var column string
			if err := columnRows.Scan(&column); err != nil {
				_ = columnRows.Close()
				t.Fatal(err)
			}
			for _, retired := range []string{"directory", "surface", "business_workspace", "tenant_admin", "portal"} {
				if strings.Contains(strings.ToLower(column), retired) {
					t.Errorf("fresh Identity table %q retains retired column %q", table, column)
				}
			}
			if column == "audience" && table != "_identity_auth_refresh_tokens" {
				t.Errorf("fresh Identity table %q retains non-auth audience column", table)
			}
		}
		if err := columnRows.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIdentitySchemaOwnershipMatchesFreshPhysicalPrimaryKeys(t *testing.T) {
	tables := identityschema.SchemaOwnership()
	if err := schemaownership.ValidateAll(tables); err != nil {
		t.Fatal(err)
	}
	if len(tables) != 22 {
		t.Fatalf("Identity owned table count=%d, want 22", len(tables))
	}
	store, err := database.OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite",
		DBPath:         filepath.Join(t.TempDir(), "identity.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		rows, err := store.DB().QueryContext(t.Context(), `SELECT name FROM pragma_table_info(?) WHERE pk > 0 ORDER BY pk`, table.Name)
		if err != nil {
			t.Fatal(err)
		}
		actual := []string{}
		for rows.Next() {
			var column string
			if err := rows.Scan(&column); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			actual = append(actual, column)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if strings.Join(actual, ",") != strings.Join(table.PrimaryKey, ",") {
			t.Errorf("table %s physical primary key=%v, ownership=%v", table.Name, actual, table.PrimaryKey)
		}
	}
}

func TestIdentityOwnershipCatalogRejectsPlaneBusinessTables(t *testing.T) {
	for _, table := range identityschema.IdentityTableOwnership() {
		if table.Name == "_schema_migrations" {
			t.Error("host migration ledger must not be claimed by the Identity module")
		}
		for _, prefix := range []string{"record_", "workflow_", "automation_", "notification_", "party_", "integration_"} {
			if len(table.Name) >= len(prefix) && table.Name[:len(prefix)] == prefix {
				t.Errorf("Plane-owned table %q leaked into Identity ownership catalog", table.Name)
			}
		}
	}
}
