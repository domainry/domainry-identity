package identity_test

import (
	"path/filepath"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestDisableIdentityAccountRevokesSessionsAtomicallyAndPreservesBusinessFacts(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "disable-account.db")})
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
	if err := store.UpsertIdentityUser(t.Context(), "default", identitymodel.IdentityUser{ID: "user-1", Name: "Dual Identity", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityWorkforceProfile(t.Context(), "default", identitymodel.IdentityWorkforceProfile{
		ID: "workforce-1", OrganizationID: "org-1", IdentityUserID: "user-1", WorkerNo: "E-1",
		WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `INSERT INTO identity_profile_bindings
		(id, workspace_id, binding_key, object_key, profile_id, identity_user_id, status, version, created_at, updated_at)
		VALUES ('binding-1','default','member','member_profile','member-1','user-1','active',1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `INSERT INTO auth_refresh_tokens
		(id, workspace_id, user_id, session_id, token_hash, expires_at, created_at, updated_at)
		VALUES
		('token-b','default','user-1','b-console-session','hash-b','2999-01-01T00:00:00Z','now','now'),
		('token-c','default','user-1','c-portal-session','hash-c','2999-01-01T00:00:00Z','now','now'),
		('token-other','default','other-user','other-session','hash-other','2999-01-01T00:00:00Z','now','now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `CREATE TRIGGER fail_account_session_revoke BEFORE UPDATE ON auth_refresh_tokens
		BEGIN SELECT RAISE(ABORT, 'injected session revoke failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DisableIdentityAccount(t.Context(), "default", "user-1"); err == nil {
		t.Fatal("injected session revoke failure was ignored")
	}
	assertIdentityAccountDisableState(t, identityStore, "active", false, "active", "active")
	if _, err := identityStore.DB().ExecContext(t.Context(), `DROP TRIGGER fail_account_session_revoke`); err != nil {
		t.Fatal(err)
	}
	revoked, err := store.DisableIdentityAccount(t.Context(), "default", "user-1")
	if err != nil || revoked != 2 {
		t.Fatalf("revoked=%d err=%v", revoked, err)
	}
	assertIdentityAccountDisableState(t, identityStore, "disabled", true, "active", "active")
	application := identityapplication.NewIdentityApplicationService(store, nil)
	if err := application.EnableUser(requestcontext.WithWorkspaceID(t.Context(), "default"), "user-1"); err != nil {
		t.Fatal(err)
	}
	assertIdentityAccountDisableState(t, identityStore, "active", true, "active", "active")
}

func assertIdentityAccountDisableState(t *testing.T, store *persistence.IdentityStore, userStatus string, sessionRevoked bool, workforceStatus, bindingStatus string) {
	t.Helper()
	var gotUser, gotWorkforce, gotBinding string
	var activeTargetSessions, revokedTargetSessions, revokedOtherSessions int
	if err := store.DB().QueryRow(`SELECT status FROM identity_users WHERE id='user-1'`).Scan(&gotUser); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRow(`SELECT
		SUM(CASE WHEN revoked_at IS NULL OR revoked_at = '' THEN 1 ELSE 0 END),
		SUM(CASE WHEN revoked_at IS NOT NULL AND revoked_at <> '' THEN 1 ELSE 0 END)
		FROM auth_refresh_tokens WHERE workspace_id='default' AND user_id='user-1'`).Scan(&activeTargetSessions, &revokedTargetSessions); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM auth_refresh_tokens
		WHERE id='token-other' AND revoked_at IS NOT NULL AND revoked_at <> ''`).Scan(&revokedOtherSessions); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRow(`SELECT work_status FROM identity_workforce_profiles WHERE id='workforce-1'`).Scan(&gotWorkforce); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRow(`SELECT status FROM identity_profile_bindings WHERE id='binding-1'`).Scan(&gotBinding); err != nil {
		t.Fatal(err)
	}
	wantActive, wantRevoked := 2, 0
	if sessionRevoked {
		wantActive, wantRevoked = 0, 2
	}
	if gotUser != userStatus || activeTargetSessions != wantActive || revokedTargetSessions != wantRevoked ||
		revokedOtherSessions != 0 || gotWorkforce != workforceStatus || gotBinding != bindingStatus {
		t.Fatalf("user=%s target_active=%d target_revoked=%d other_revoked=%d workforce=%s binding=%s",
			gotUser, activeTargetSessions, revokedTargetSessions, revokedOtherSessions, gotWorkforce, gotBinding)
	}
}
