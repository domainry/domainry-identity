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
	for _, required := range []string{"identity_users", "identity_roles", "identity_departments", "identity_menus", "identity_credentials", "identity_metadata_refresh_intents"} {
		if !tables[required] {
			t.Errorf("required Identity table %q is missing", required)
		}
	}
	for _, moduleOwned := range []string{"object_definitions", "field_definitions", "validation_definitions", "action_definitions", "dictionary_definitions"} {
		if tables[moduleOwned] {
			t.Errorf("Metadata Module table %q leaked from Identity-owned schema assembly", moduleOwned)
		}
	}
	for _, forbidden := range []string{"frontend_capability_manifests", "view_definitions", "_workflow_executions", "automation_rule_executions", "integration_outbox_messages", "transaction_boundary_intents", "notification_events", "notification_inbox_items", "scheduler_definitions", "report_snapshots", "party_parties", "lifecycle_cleanup_jobs", "business_record_localized_value"} {
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

func TestIdentitySchemaConsolidatesLegacyDefinitionVersionsIntoMetadataModule(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.DB().ExecContext(t.Context(), `CREATE TABLE identity_definition_versions (
		id TEXT PRIMARY KEY,
		resource_type TEXT NOT NULL,
		resource_key TEXT NOT NULL,
		schema_version TEXT NOT NULL,
		schema_hash TEXT NOT NULL,
		payload_json TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO identity_definition_versions
		(id, resource_type, resource_key, schema_version, schema_hash, payload_json, created_at)
		VALUES ('role:admin:v1', 'role', 'admin', '1', 'hash-v1', '{"key":"admin"}', '2026-08-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	var migrated int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM metadata_definition_versions WHERE id='role:admin:v1' AND resource_type='role' AND resource_key='admin'`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated != 1 {
		t.Fatalf("migrated role definition versions=%d want=1", migrated)
	}
	var legacyTableCount int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='identity_definition_versions'`).Scan(&legacyTableCount); err != nil {
		t.Fatal(err)
	}
	if legacyTableCount != 0 {
		t.Fatalf("legacy Identity definition version table count=%d want=0", legacyTableCount)
	}
}
