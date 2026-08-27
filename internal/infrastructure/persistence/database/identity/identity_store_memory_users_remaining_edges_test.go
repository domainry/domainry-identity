package identity

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestMemoryIdentityStoreUserBatchAndProfileBindingEdges(t *testing.T) {
	store := NewMemoryIdentityStore()
	if _, err := store.ListIdentityProfileBindingsByUser(t.Context(), "", "user-1"); err == nil {
		t.Fatal("expected invalid workspace error")
	}
	if bindings, err := store.ListIdentityProfileBindingsByUser(t.Context(), "workspace-a", "user-1"); err != nil || len(bindings) != 0 {
		t.Fatalf("bindings=%#v err=%v", bindings, err)
	}
	if err := store.UpsertIdentityUsersAtomically(t.Context(), "", nil); err == nil {
		t.Fatal("expected invalid workspace error")
	}
	if err := store.UpsertIdentityUsersAtomically(t.Context(), "workspace-a", []identitymodel.IdentityUser{{}}); err == nil {
		t.Fatal("expected missing user id error")
	}

	users := []identitymodel.IdentityUser{
		{ID: "user-1"},
		{ID: "user-2", Status: identitymodel.IdentityStatusDisabled, AccountType: identitymodel.IdentityAccountService},
	}
	if err := store.UpsertIdentityUsersAtomically(t.Context(), "workspace-a", users); err != nil {
		t.Fatal(err)
	}
	first, found, err := store.GetIdentityUser(t.Context(), "workspace-a", "user-1")
	if err != nil || !found || first.Status != identitymodel.IdentityStatusActive || first.AccountType != identitymodel.IdentityAccountHuman || first.Version != 1 {
		t.Fatalf("first=%#v found=%t err=%v", first, found, err)
	}
	if err := store.UpsertIdentityUsersAtomically(t.Context(), "workspace-a", []identitymodel.IdentityUser{{
		ID: "user-1", Status: identitymodel.IdentityStatusDisabled, AccountType: identitymodel.IdentityAccountAutomation,
	}}); err != nil {
		t.Fatal(err)
	}
	updated, found, err := store.GetIdentityUser(t.Context(), "workspace-a", "user-1")
	if err != nil || !found || updated.Version != 2 || updated.CreatedAt != first.CreatedAt || updated.Status != identitymodel.IdentityStatusDisabled || updated.AccountType != identitymodel.IdentityAccountAutomation {
		t.Fatalf("updated=%#v found=%t err=%v", updated, found, err)
	}
}

func TestMemoryIdentityStoreUserRoleAssignmentAtomicEdges(t *testing.T) {
	store := NewMemoryIdentityStore()
	if err := store.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "", identitymodel.IdentityUser{ID: "user-1"}, nil); err == nil {
		t.Fatal("expected invalid workspace error")
	}
	if err := store.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "workspace-a", identitymodel.IdentityUser{}, nil); err == nil {
		t.Fatal("expected missing user id error")
	}
	if err := store.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "workspace-a", identitymodel.IdentityUser{ID: "user-1"}, []identitymodel.IdentityUserRoleAssignment{{UserID: "other", RoleID: "role-a"}}); err == nil {
		t.Fatal("expected mismatched user id error")
	}
	if err := store.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "workspace-a", identitymodel.IdentityUser{ID: "user-1"}, []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1"}}); err == nil {
		t.Fatal("expected missing role id error")
	}

	assignments := []identitymodel.IdentityUserRoleAssignment{
		{UserID: "user-1", RoleID: "role-a"},
		{UserID: "user-1", RoleID: "role-b", Source: "sync", Status: "disabled"},
	}
	if err := store.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "workspace-a", identitymodel.IdentityUser{ID: "user-1"}, assignments); err != nil {
		t.Fatal(err)
	}
	prefix, _ := identityWorkspacePrefix("workspace-a")
	if got := store.userRoles[prefix+"user-1\x00role-a"]; got.Source != "manual" || got.Status != "active" {
		t.Fatalf("default assignment=%#v", got)
	}
	if got := store.userRoles[prefix+"user-1\x00role-b"]; got.Source != "sync" || got.Status != "disabled" {
		t.Fatalf("explicit assignment=%#v", got)
	}
	created := store.users[prefix+"user-1"]
	if created.Version != 1 || created.Status != identitymodel.IdentityStatusActive || created.AccountType != identitymodel.IdentityAccountHuman {
		t.Fatalf("created user=%#v", created)
	}

	otherPrefix, _ := identityWorkspacePrefix("workspace-b")
	store.userRoles[prefix+"other\x00role-x"] = identitymodel.IdentityUserRoleAssignment{UserID: "other", RoleID: "role-x"}
	store.userRoles[otherPrefix+"user-1\x00role-y"] = identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "role-y"}
	if err := store.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "workspace-a", identitymodel.IdentityUser{
		ID: "user-1", Status: identitymodel.IdentityStatusDisabled, AccountType: identitymodel.IdentityAccountService,
	}, []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "role-c"}}); err != nil {
		t.Fatal(err)
	}
	updated := store.users[prefix+"user-1"]
	if updated.Version != 2 || updated.CreatedAt != created.CreatedAt || updated.Status != identitymodel.IdentityStatusDisabled || updated.AccountType != identitymodel.IdentityAccountService {
		t.Fatalf("updated user=%#v", updated)
	}
	if _, ok := store.userRoles[prefix+"user-1\x00role-a"]; ok {
		t.Fatal("stale assignment was not removed")
	}
	if _, ok := store.userRoles[prefix+"other\x00role-x"]; !ok {
		t.Fatal("same-workspace other-user assignment was removed")
	}
	if _, ok := store.userRoles[otherPrefix+"user-1\x00role-y"]; !ok {
		t.Fatal("other-workspace assignment was removed")
	}
}
