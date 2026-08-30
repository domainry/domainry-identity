package identity_test

import (
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityUserRemovalRollsBackEveryOwnedTable(t *testing.T) {
	identityStore, err := OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite",
		DBPath:         filepath.Join(t.TempDir(), "identity-user-delete.db"),
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
	user := identitymodel.IdentityUser{ID: "user-1", Name: "User", Status: identitymodel.IdentityStatusActive}
	if err := repository.UpsertIdentityUser(t.Context(), "default", user); err != nil {
		t.Fatal(err)
	}
	if err := repository.AssignIdentityUserRole(t.Context(), "default", identitymodel.IdentityUserRoleAssignment{UserID: user.ID, RoleID: "role-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), "INSERT INTO _identity_mfa_factors (id, workspace_id, user_id, factor_type, status, verified_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", "factor-1", "default", user.ID, "totp", "active", "now", "now", "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `CREATE TRIGGER reject_identity_user_delete BEFORE DELETE ON _identity_users
		WHEN OLD.id = 'user-1' BEGIN SELECT RAISE(ABORT, 'injected user delete failure'); END`); err != nil {
		t.Fatal(err)
	}

	if err := repository.RemoveIdentityUser(t.Context(), "default", user.ID); err == nil {
		t.Fatal("trigger failure did not abort user removal")
	}
	if _, found, err := repository.GetIdentityUser(t.Context(), "default", user.ID); err != nil || !found {
		t.Fatalf("user was partially removed: found=%v err=%v", found, err)
	}
	assignments, err := repository.ListIdentityUserRoleAssignments(t.Context(), "default", user.ID)
	if err != nil || len(assignments) != 1 || assignments[0].RoleID != "role-1" {
		t.Fatalf("role assignment was partially removed: assignments=%+v err=%v", assignments, err)
	}
	var mfaCount int
	if err := identityStore.DB().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM _identity_mfa_factors WHERE workspace_id = ? AND user_id = ?", "default", user.ID).Scan(&mfaCount); err != nil || mfaCount != 1 {
		t.Fatalf("MFA factor was partially removed: count=%d err=%v", mfaCount, err)
	}

	if _, err := identityStore.DB().ExecContext(t.Context(), `DROP TRIGGER reject_identity_user_delete`); err != nil {
		t.Fatal(err)
	}
	if err := repository.RemoveIdentityUser(t.Context(), "default", user.ID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := repository.GetIdentityUser(t.Context(), "default", user.ID); err != nil || found {
		t.Fatalf("committed removal found=%v err=%v", found, err)
	}
	if err := identityStore.DB().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM _identity_mfa_factors WHERE workspace_id = ? AND user_id = ?", "default", user.ID).Scan(&mfaCount); err != nil || mfaCount != 0 {
		t.Fatalf("committed removal retained MFA factor: count=%d err=%v", mfaCount, err)
	}
}
