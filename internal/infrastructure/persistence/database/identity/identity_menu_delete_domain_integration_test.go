package identity_test

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	identitybusiness "github.com/domainry/domainry-identity/internal/domain/identity/service"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestIdentityServiceRemoveMenuDeletesDescendantsAndRoleAssignments(t *testing.T) {
	store := identitypersistence.NewMemoryIdentityStore()
	identity, _ := identitybusiness.NewIdentityDomainService(store, nil).ForWorkspace(identitymodel.InstallationWorkspaceID)
	identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "admin", Name: "Admin", Permissions: []string{"workspace.admin"}},
	})
	for _, role := range []identitymodel.IdentityRole{{ID: "admin", Key: "admin", Label: "Admin"}} {
		seedIdentityDirectoryRole(t, store, identitymodel.InstallationWorkspaceID, role)
	}
	for _, menu := range []identitymodel.IdentityMenu{
		{ID: "parent", Key: "parent-key", Label: "Parent"},
		{ID: "child", Key: "child-key", Label: "Child", ParentID: "parent"},
		{ID: "grandchild", Key: "grandchild-key", Label: "Grandchild", ParentID: "child"},
		{ID: "sibling", Key: "sibling-key", Label: "Sibling"},
	} {
		if err := identity.UpsertMenu(t.Context(), menu); err != nil {
			t.Fatalf("upsert menu %s: %v", menu.ID, err)
		}
	}
	if err := identity.SetRoleMenus(t.Context(), "admin", []string{"parent", "child-key", "grandchild", "sibling"}); err != nil {
		t.Fatalf("set role menus: %v", err)
	}

	deleted, err := identity.RemoveMenu(t.Context(), "parent")
	if err != nil {
		t.Fatalf("remove menu tree: %v", err)
	}
	if len(deleted) != 3 || deleted[0] != "grandchild" || deleted[1] != "child" || deleted[2] != "parent" {
		t.Fatalf("expected children-first deletion, got %#v", deleted)
	}
	menus, err := identity.ListMenus(t.Context())
	if err != nil {
		t.Fatalf("list menus: %v", err)
	}
	if len(menus) != 1 || menus[0].ID != "sibling" {
		t.Fatalf("deleted menus should not remain visible, got %#v", menus)
	}
	assignments, err := identity.ListRoleMenuAssignments(t.Context(), "admin")
	if err != nil {
		t.Fatalf("list role menus: %v", err)
	}
	if len(assignments) != 1 || assignments[0].MenuID != "sibling" {
		t.Fatalf("deleted menu assignments should be removed, got %#v", assignments)
	}
}
