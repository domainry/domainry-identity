package identity_test

import (
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestRemoveIdentityUserRollsBackEveryOwnedSecurityFact(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "remove-user.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityUser(t.Context(), "default", identitymodel.IdentityUser{ID: "user-1", Name: "Delete Me", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignIdentityUserRole(t.Context(), "default", identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "role-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `INSERT INTO _identity_auth_refresh_tokens
		(id, workspace_id, user_id, session_id, token_hash, expires_at, created_at, updated_at)
		VALUES ('token-1','default','user-1','session-1','hash','2999-01-01T00:00:00Z','now','now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `CREATE TRIGGER fail_identity_user_delete BEFORE DELETE ON _identity_users
		BEGIN SELECT RAISE(ABORT, 'injected identity delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveIdentityUser(t.Context(), "default", "user-1"); err == nil {
		t.Fatal("injected identity delete failure was ignored")
	}
	assertIdentityUserOwnedRows(t, identityStore, 1)
	if _, err := identityStore.DB().ExecContext(t.Context(), `DROP TRIGGER fail_identity_user_delete`); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveIdentityUser(t.Context(), "default", "user-1"); err != nil {
		t.Fatal(err)
	}
	assertIdentityUserOwnedRows(t, identityStore, 0)
}

func assertIdentityUserOwnedRows(t *testing.T, store *persistence.IdentityStore, expected int) {
	t.Helper()
	for _, query := range []string{
		`SELECT COUNT(*) FROM _identity_users WHERE id='user-1'`,
		`SELECT COUNT(*) FROM _identity_user_role_assignments WHERE user_id='user-1'`,
		`SELECT COUNT(*) FROM _identity_auth_refresh_tokens WHERE user_id='user-1'`,
	} {
		var count int
		if err := store.DB().QueryRowContext(t.Context(), query).Scan(&count); err != nil || count != expected {
			t.Fatalf("query=%q count=%d expected=%d err=%v", query, count, expected, err)
		}
	}
}
