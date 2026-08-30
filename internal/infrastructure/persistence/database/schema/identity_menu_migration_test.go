package schema_test

import (
	"path/filepath"
	"testing"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentitySchemaDropsLegacyMenuAudienceWithoutLosingMenus(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite",
		DBPath:         filepath.Join(t.TempDir(), "identity-menu.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := identityschema.EnsureIdentitySchema(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `ALTER TABLE _identity_menus ADD COLUMN audience TEXT NOT NULL DEFAULT 'admin_console'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO _identity_menus (id, workspace_id, menu_key, label, icon, route, parent_id, sort_order, status, created_at, updated_at, audience) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"menu-1", "workspace-1", "accounts", "Accounts", "users", "/admin/accounts", nil, 10, "active", "2026-07-26T00:00:00Z", "2026-07-26T00:00:00Z", "admin_console",
	); err != nil {
		t.Fatal(err)
	}
	if err := identityschema.EnsureIdentitySchema(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	var audienceColumnCount int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pragma_table_info('_identity_menus') WHERE name = 'audience'`).Scan(&audienceColumnCount); err != nil {
		t.Fatal(err)
	}
	var menuCount int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_menus WHERE id = 'menu-1'`).Scan(&menuCount); err != nil {
		t.Fatal(err)
	}
	if audienceColumnCount != 0 || menuCount != 1 {
		t.Fatalf("audience columns=%d preserved menus=%d", audienceColumnCount, menuCount)
	}
}
