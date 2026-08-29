package identity_test

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	"testing"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestMemoryIdentityStoreRoleAssignments(t *testing.T) {
	store := identitypersistence.NewMemoryIdentityStore()
	if err := store.UpsertIdentityUser(t.Context(), identitymodel.InstallationWorkspaceID, identitymodel.IdentityUser{ID: "u-admin", Name: "Admin", Email: "admin@example.com"}); err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if err := store.UpsertIdentityRole(t.Context(), identitymodel.InstallationWorkspaceID, identitymodel.IdentityRole{ID: "r-admin", Key: "admin", Label: "Admin"}); err != nil {
		t.Fatalf("upsert role: %v", err)
	}
	if err := store.AssignIdentityUserRole(t.Context(), identitymodel.InstallationWorkspaceID, identitymodel.IdentityUserRoleAssignment{UserID: "u-admin", RoleID: "r-admin"}); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := store.AssignIdentityUserRole(t.Context(), identitymodel.InstallationWorkspaceID, identitymodel.IdentityUserRoleAssignment{UserID: "u-admin", RoleID: "r-admin"}); err != nil {
		t.Fatalf("assign duplicate role: %v", err)
	}
	assignments, err := store.ListIdentityUserRoleAssignments(t.Context(), identitymodel.InstallationWorkspaceID, "u-admin")
	if err != nil {
		t.Fatalf("list role assignments: %v", err)
	}
	if len(assignments) != 1 {
		t.Fatalf("expected duplicate role assignments to be de-duplicated, got %#v", assignments)
	}
}
