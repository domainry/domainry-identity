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
	for _, required := range []string{"identity_users", "identity_roles", "identity_departments", "identity_menus", "identity_credentials", "object_definitions", "field_definitions", "identity_metadata_refresh_intents", "_audit_events"} {
		if !tables[required] {
			t.Errorf("required Identity table %q is missing", required)
		}
	}
	for _, forbidden := range []string{"frontend_capability_manifests", "_workflow_executions", "automation_rule_executions", "integration_outbox_messages", "transaction_boundary_intents", "notification_events", "notification_inbox_items", "scheduler_definitions", "report_snapshots", "party_parties", "lifecycle_cleanup_jobs", "business_record_localized_value"} {
		if tables[forbidden] {
			t.Errorf("Plane table %q leaked into standalone Identity schema", forbidden)
		}
	}
}

func TestFrontendCapabilityRegistryMigrationRemovesRetiredTable(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.DB().ExecContext(t.Context(), `CREATE TABLE frontend_capability_manifests (workspace_id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := identityschema.RemoveFrontendCapabilityRegistry(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'frontend_capability_manifests'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("retired frontend capability registry still exists")
	}
}
