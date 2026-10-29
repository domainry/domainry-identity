package schema_test

import (
	"path/filepath"
	"testing"
	"time"

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
	insertPermission := func() error {
		statement, arguments, err := query.NewInsertBuilder(store.BuilderRenderer(), "_identity_permissions").
			Columns("permission_key", "module_key", "group_key", "resource_key", "operation_key", "label", "description", "category", "source_kind", "source_owner", "grant_mode", "scope_kind", "object_key", "default_locale", "i18n_json", "definition_status", "enabled", "definition_hash", "source_snapshot_hash", "created_at", "updated_at").
			Values("customer.read", "business", "customer", "customer", "read", "Read customers", "", "record", "builder", "project", "direct", "record", "customer", "en", `{"en":{"module_label":"Business","group_label":"Customers","resource_label":"Customers","operation_label":"Read","label":"Read customers"}}`, "active", true, "definition-hash", "snapshot-hash", time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC).UnixMilli(), time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC).UnixMilli()).
			Build()
		if err != nil {
			return err
		}
		_, err = store.DB().ExecContext(t.Context(), statement, arguments...)
		return err
	}
	if err := insertPermission(); err != nil {
		t.Fatal(err)
	}
	if err := insertPermission(); err == nil {
		t.Fatal("database accepted duplicate global permission_key")
	}
}
