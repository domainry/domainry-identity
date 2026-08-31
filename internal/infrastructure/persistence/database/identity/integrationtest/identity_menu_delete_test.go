package identity_test

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"

	"path/filepath"
	"testing"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestSQLIdentityMenuDeletionSurvivesReloadAndSeedSync(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-menu-delete.db")})
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
	menu := identitymodel.IdentityMenu{ID: "manifest-menu", Key: "manifest_menu", Label: "Manifest menu", Status: identitymodel.IdentityStatusActive}
	if err := identityStore.UpsertIdentityMenu(t.Context(), "workspace-primary", menu); err != nil {
		t.Fatalf("seed menu: %v", err)
	}
	if err := identityStore.RemoveIdentityMenu(t.Context(), "workspace-primary", menu.ID); err != nil {
		t.Fatalf("delete menu: %v", err)
	}
	if err := identityStore.UpsertIdentityMenu(t.Context(), "workspace-primary", menu); err != nil {
		t.Fatalf("repeat manifest sync: %v", err)
	}
	reloaded, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatalf("reload identity store: %v", err)
	}
	menus, err := reloaded.ListIdentityMenus(t.Context(), "workspace-primary")
	if err != nil {
		t.Fatalf("list menus: %v", err)
	}
	if len(menus) != 0 {
		t.Fatalf("expected deleted menu to stay hidden, got %#v", menus)
	}
}

func TestSQLIdentityAtomicMenuTreeRollback(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-atomic.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	parent := identitymodel.IdentityMenu{ID: "parent", Key: "parent", Status: identitymodel.IdentityStatusActive}
	child := identitymodel.IdentityMenu{ID: "child", Key: "child", ParentID: parent.ID, Status: identitymodel.IdentityStatusActive}
	if err := identityStore.UpsertIdentityMenu(t.Context(), "workspace-primary", parent); err != nil {
		t.Fatal(err)
	}
	if err := identityStore.UpsertIdentityMenu(t.Context(), "workspace-primary", child); err != nil {
		t.Fatal(err)
	}
	missing := identitymodel.IdentityMenu{ID: "missing", Key: "missing"}
	if err := identityStore.RemoveIdentityMenusAtomically(t.Context(), "workspace-primary", []identitymodel.IdentityMenu{child, parent, missing}); err == nil {
		t.Fatal("expected missing menu to roll back tree deletion")
	}
	reloaded, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	menus, err := reloaded.ListIdentityMenus(t.Context(), "workspace-primary")
	if err != nil || len(menus) != 2 {
		t.Fatalf("menu tree partially deleted: menus=%#v err=%v", menus, err)
	}
}
