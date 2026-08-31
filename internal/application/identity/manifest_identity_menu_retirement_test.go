package identity

import (
	"path/filepath"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestRetireRemovedPlatformIdentityMenusDeletesLegacyTree(t *testing.T) {
	store, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "retired-menu.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatalf("ensure identity schema: %v", err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatalf("open identity store: %v", err)
	}
	for _, menu := range []identitymodel.IdentityMenu{
		{ID: "org_permissions", Key: "org_permissions", Label: "Permissions", Status: identitymodel.IdentityStatusActive},
		{ID: "legacy_child", Key: "legacy_child", Label: "Legacy child", ParentID: "org_permissions", Status: identitymodel.IdentityStatusActive},
		{ID: "org_roles", Key: "org_roles", Label: "Roles", Status: identitymodel.IdentityStatusActive},
	} {
		if err := identityStore.UpsertIdentityMenu(t.Context(), "workspace-primary", menu); err != nil {
			t.Fatalf("seed menu %s: %v", menu.ID, err)
		}
	}
	if err := retireRemovedPlatformIdentityMenus(requestcontext.WithWorkspaceID(t.Context(), "workspace-primary"), identityStore); err != nil {
		t.Fatalf("retire removed platform menu: %v", err)
	}
	menus, err := identityStore.ListIdentityMenus(t.Context(), "workspace-primary")
	if err != nil {
		t.Fatalf("list menus: %v", err)
	}
	if len(menus) != 1 || menus[0].ID != "org_roles" {
		t.Fatalf("expected only unrelated menu to remain, got %#v", menus)
	}
	reloaded, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatalf("reload identity store: %v", err)
	}
	menus, err = reloaded.ListIdentityMenus(t.Context(), "workspace-primary")
	if err != nil {
		t.Fatalf("list reloaded menus: %v", err)
	}
	if len(menus) != 1 || menus[0].ID != "org_roles" {
		t.Fatalf("retired menus must stay hidden after reload, got %#v", menus)
	}
}
