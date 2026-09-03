package schema_test

import (
	"path/filepath"
	"testing"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
	"github.com/domainry/domainry-orm/query"
)

func TestIdentityPermissionNaturalKeyRejectsDuplicateRows(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "permission-unique.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	insertPermission := func(id string) error {
		statement, arguments, err := query.NewWorkspaceInsertBuilder(store.BuilderRenderer(), "_identity_permissions", "workspace-a").
			Columns("id", "permission_key", "resource_key", "operation_key", "label", "description", "category", "source_kind", "source_owner", "definition_status", "enabled", "definition_hash", "source_snapshot_hash", "created_at", "updated_at").
			Values(id, "customer.read", "customer", "read", "Read customers", "", "record", "builder", "project", "active", true, "definition-hash", "snapshot-hash", "2026-09-03T00:00:00Z", "2026-09-03T00:00:00Z").
			Build()
		if err != nil {
			return err
		}
		_, err = store.DB().ExecContext(t.Context(), statement, arguments...)
		return err
	}
	if err := insertPermission("permission-one"); err != nil {
		t.Fatal(err)
	}
	if err := insertPermission("permission-two"); err == nil {
		t.Fatal("database accepted duplicate (workspace_id, permission_key) with a different technical id")
	}
}
