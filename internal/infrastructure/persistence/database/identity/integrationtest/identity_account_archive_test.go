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

func TestSQLArchivePreservesHistoryRevokesAccessAndCannotBeReactivated(t *testing.T) {
	db, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "archive.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), db.DB(), db.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	scope := identitymodel.IdentityDataScopeFilter{Unrestricted: true}
	for _, ws := range []string{"workspace-primary", "workspace-other"} {
		if err := store.UpsertIdentityUser(t.Context(), ws, identitymodel.IdentityUser{ID: "departed", Name: "Retained Name", Email: "departed-" + ws + "@example.test", OrgID: "dept", Status: identitymodel.IdentityStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	// Raw SQL below is fixture/fault-injection evidence, never production DML.
	for _, statement := range []string{
		`INSERT INTO _identity_profile_bindings (id,workspace_id,binding_key,object_key,profile_id,identity_user_id,status,version,created_at,updated_at) VALUES ('binding','workspace-primary','member','member_profile','history-1','departed','active',1,1,1)`,
		`INSERT INTO _identity_auth_refresh_tokens (id,workspace_id,user_id,session_id,token_hash,expires_at,created_at,updated_at) VALUES ('token','workspace-primary','departed','session','hash',32503680000000,1,1)`,
		`CREATE TRIGGER fail_archive_session BEFORE UPDATE ON _identity_auth_refresh_tokens BEGIN SELECT RAISE(ABORT,'injected archive failure'); END`,
	} {
		if _, err := db.DB().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.ArchiveIdentityAccountWithinDataScope(t.Context(), "workspace-primary", "departed", 1, scope); err == nil {
		t.Fatal("partial archive committed")
	}
	user, _, _ := store.GetIdentityUser(t.Context(), "workspace-primary", "departed")
	if user.Status != identitymodel.IdentityStatusActive || user.Version != 1 {
		t.Fatal("failed transaction changed account")
	}
	if _, err := db.DB().ExecContext(t.Context(), `DROP TRIGGER fail_archive_session`); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ArchiveIdentityAccountWithinDataScope(t.Context(), "workspace-primary", "departed", 99, scope); err == nil || found {
		t.Fatal("stale version accepted")
	}
	if _, found, err := store.ArchiveIdentityAccountWithinDataScope(t.Context(), "workspace-primary", "departed", 1, identitymodel.IdentityDataScopeFilter{OwnerOrgIDs: []string{"other-dept"}}); err != nil || found {
		t.Fatal("out-of-scope account archived")
	}
	revoked, found, err := store.ArchiveIdentityAccountWithinDataScope(t.Context(), "workspace-primary", "departed", 1, scope)
	if err != nil || !found || revoked != 1 {
		t.Fatalf("archive revoked=%d found=%v err=%v", revoked, found, err)
	}
	user, found, err = store.GetIdentityUser(t.Context(), "workspace-primary", "departed")
	if err != nil || !found || user.Status != identitymodel.IdentityStatusDeleted || user.Name != "Retained Name" {
		t.Fatalf("history identity lost: %+v %v", user, err)
	}
	other, _, _ := store.GetIdentityUser(t.Context(), "workspace-other", "departed")
	if other.Status != identitymodel.IdentityStatusActive {
		t.Fatal("other workspace affected")
	}
	var binding string
	if err := db.DB().QueryRow(`SELECT status FROM _identity_profile_bindings WHERE id='binding'`).Scan(&binding); err != nil || binding != "active" {
		t.Fatal("business identity changed")
	}
	page, err := store.SearchIdentityUsersWithinDataScope(t.Context(), "workspace-primary", identitymodel.IdentityListQuery{PageSize: 10}, scope)
	if err != nil || page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("normal directory includes deleted account: %+v %v", page, err)
	}
	if revoked, found, err = store.ArchiveIdentityAccountWithinDataScope(t.Context(), "workspace-primary", "departed", 1, scope); err != nil || !found || revoked != 0 {
		t.Fatal("duplicate archive not idempotent")
	}
	if err := store.SetIdentityUserStatus(t.Context(), "workspace-primary", "departed", identitymodel.IdentityStatusActive); err == nil {
		t.Fatal("deleted user enabled")
	}
	user.Status = identitymodel.IdentityStatusActive
	if err := store.UpsertIdentityUser(t.Context(), "workspace-primary", user); err == nil {
		t.Fatal("upsert restored deleted user")
	}
	app := identityapplication.NewIdentityApplicationService(store, nil)
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-other")
	actor := identitymodel.Principal{Known: true, UserID: "departed", WorkspaceID: "workspace-other"}
	if _, err := app.ArchiveUserWithinDataScope(ctx, "departed", 1, actor); err == nil {
		t.Fatal("self archive allowed")
	}
}
