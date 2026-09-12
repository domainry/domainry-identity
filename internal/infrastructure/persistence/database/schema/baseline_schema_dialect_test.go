package schema

import (
	"strings"
	"testing"
)

type dialectScriptedSchemaStore struct{ scriptedSchemaStore }

func (s dialectScriptedSchemaStore) Identifier(value string) string {
	return s.SchemaRenderer().Identifier(value)
}

func (s dialectScriptedSchemaStore) TableIdentifier(value string) string {
	return s.SchemaRenderer().Table(value)
}

func (s dialectScriptedSchemaStore) Placeholder(position int) string {
	return s.SchemaRenderer().Placeholder(position)
}

func TestBaselinePhysicalSchemaDDLHasThreeDialectCoverage(t *testing.T) {
	for _, driver := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			state := &schemaSQLState{}
			database := openSchemaScriptedDB(state)
			t.Cleanup(func() { _ = database.Close() })
			store := dialectScriptedSchemaStore{scriptedSchemaStore{db: database, driver: driver}}
			if err := EnsureMetadataSchema(t.Context(), store); err != nil {
				t.Fatalf("metadata schema: %v", err)
			}
			if err := EnsureIdentitySchema(t.Context(), store); err != nil {
				t.Fatalf("identity schema: %v", err)
			}
			rendered := strings.Join(state.execQueries, "\n")
			if !strings.Contains(rendered, "CREATE TABLE IF NOT EXISTS") ||
				!strings.Contains(rendered, store.TableIdentifier("_identity_users")) ||
				!strings.Contains(rendered, store.TableIdentifier("_identity_organization_unit_delivery_states")) ||
				!strings.Contains(rendered, store.TableIdentifier("_identity_organization_unit_deliveries")) ||
				!strings.Contains(rendered, store.TableIdentifier("_identity_metadata_refresh_intents")) ||
				!strings.Contains(rendered, "ALTER TABLE "+store.TableIdentifier("_identity_workspace_bootstrap_receipts")) ||
				!strings.Contains(rendered, "login_name_key") ||
				!strings.Contains(rendered, "role_catalog_sha256") ||
				!strings.Contains(rendered, "initial_workspace_administrator_role_key") {
				t.Fatalf("baseline physical DDL was not rendered through %s identifiers", driver)
			}
		})
	}
}
