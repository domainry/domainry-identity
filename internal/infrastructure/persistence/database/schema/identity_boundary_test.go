package schema_test

import (
	"path/filepath"
	"testing"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestStandaloneIdentitySchemaDoesNotCreatePlaneTables(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for _, ensure := range []func() error{
		func() error { return identityschema.EnsureMetadataSchema(t.Context(), store) },
		func() error { return identityschema.EnsureIdentitySchema(t.Context(), store) },
		func() error { return identityschema.EnsureEvidenceSchema(t.Context(), store) },
	} {
		if err := ensure(); err != nil {
			t.Fatal(err)
		}
	}

	tables := map[string]bool{}
	rows, err := store.DB().QueryContext(t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		tables[table] = true
	}
	for _, required := range []string{"_identity_users", "_identity_roles", "_identity_organization_units", "_identity_menus", "_identity_credentials", "_identity_metadata_refresh_intents"} {
		if !tables[required] {
			t.Errorf("required Identity table %q is missing", required)
		}
	}
	for _, moduleOwned := range []string{"_metadata_object_definitions", "_metadata_field_definitions", "_metadata_validation_definitions", "_metadata_action_definitions", "_metadata_dictionary_definitions"} {
		if tables[moduleOwned] {
			t.Errorf("Metadata Module table %q leaked from Identity-owned schema assembly", moduleOwned)
		}
	}
	for _, forbidden := range []string{"_workflow_executions", "_automation_rule_executions", "_transaction_boundary_intents", "_notification_events", "_notification_inbox_items", "_scheduler_definitions", "_report_snapshots", "_party_parties", "_lifecycle_cleanup_jobs", "_record_localized_values"} {
		if tables[forbidden] {
			t.Errorf("Plane table %q leaked into standalone Identity schema", forbidden)
		}
	}
}
