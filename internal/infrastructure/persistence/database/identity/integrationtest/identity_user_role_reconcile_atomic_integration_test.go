package identity_test

import (
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityUserAndRoleReconcileRollsBackAsOneTransaction(t *testing.T) {
	identityStore, err := OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite",
		DBPath:         filepath.Join(t.TempDir(), "user-role-reconcile.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	original := identitymodel.IdentityUser{ID: "user-1", Name: "Original", Email: "original@example.com", Status: identitymodel.IdentityStatusActive}
	if err := repository.UpsertIdentityUser(t.Context(), "default", original); err != nil {
		t.Fatal(err)
	}
	if err := repository.AssignIdentityUserRole(t.Context(), "default", identitymodel.IdentityUserRoleAssignment{UserID: original.ID, RoleID: "original-role"}); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `CREATE TRIGGER reject_new_role BEFORE INSERT ON _identity_user_role_assignments
		WHEN NEW.role_id = 'new-role' BEGIN SELECT RAISE(ABORT, 'rejected role'); END`); err != nil {
		t.Fatal(err)
	}
	updated := identitymodel.IdentityUser{ID: original.ID, Name: "Updated", Email: "updated@example.com", Status: identitymodel.IdentityStatusActive}
	err = repository.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "default", updated, []identitymodel.IdentityUserRoleAssignment{{UserID: original.ID, RoleID: "new-role"}})
	if err == nil {
		t.Fatal("trigger failure did not abort reconcile")
	}
	user, found, err := repository.GetIdentityUser(t.Context(), "default", original.ID)
	if err != nil || !found || user.Name != original.Name || user.Email != original.Email {
		t.Fatalf("user was partially updated: user=%+v found=%v err=%v", user, found, err)
	}
	assignments, err := repository.ListIdentityUserRoleAssignments(t.Context(), "default", original.ID)
	if err != nil || len(assignments) != 1 || assignments[0].RoleID != "original-role" {
		t.Fatalf("roles were partially reconciled: roles=%+v err=%v", assignments, err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `DROP TRIGGER reject_new_role`); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "default", updated, []identitymodel.IdentityUserRoleAssignment{{UserID: original.ID, RoleID: "new-role"}}); err != nil {
		t.Fatal(err)
	}
	user, found, err = repository.GetIdentityUser(t.Context(), "default", original.ID)
	if err != nil || !found || user.Name != updated.Name {
		t.Fatalf("committed user=%+v found=%v err=%v", user, found, err)
	}
	assignments, err = repository.ListIdentityUserRoleAssignments(t.Context(), "default", original.ID)
	if err != nil || len(assignments) != 1 || assignments[0].RoleID != "new-role" {
		t.Fatalf("committed roles=%+v err=%v", assignments, err)
	}
}
