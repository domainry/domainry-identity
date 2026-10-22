package identity

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestMemoryArchiveRetainsTombstoneAndCannotResurrect(t *testing.T) {
	store := NewMemoryIdentityStore()
	ctx := t.Context()
	ws := "workspace-primary"
	scope := identitymodel.IdentityDataScopeFilter{Unrestricted: true}
	if err := store.UpsertIdentityUser(ctx, ws, identitymodel.IdentityUser{UserID: "user", Email: "user@example.test"}); err != nil {
		t.Fatal(err)
	}
	prefix, _ := identityWorkspacePrefix(ws)
	store.credentials[prefix+"user"] = identitymodel.IdentityCredential{UserID: "user"}
	store.externalAccounts[prefix+"external"] = identitymodel.IdentityExternalAccount{UserID: "user", Provider: "feishu", ProviderSubject: "union"}
	store.userRoles[prefix+"role"] = identitymodel.IdentityUserRoleAssignment{UserID: "user", RoleID: "role", Status: "active"}
	store.refreshTokens[prefix+"token"] = identitymodel.AuthRefreshToken{UserID: "user"}
	if _, _, err := store.ArchiveIdentityAccountWithinDataScope(ctx, ws, "user", 2, scope); err == nil {
		t.Fatal("stale version accepted")
	}
	if revoked, found, err := store.ArchiveIdentityAccountWithinDataScope(ctx, ws, "user", 1, scope); err != nil || !found || revoked != 1 {
		t.Fatalf("archive revoked=%d found=%v err=%v", revoked, found, err)
	}
	user, found, _ := store.GetIdentityUser(ctx, ws, "user")
	if !found || user.Status != identitymodel.IdentityStatusDeleted || user.Email != "user@example.test" {
		t.Fatal("historical identity lost")
	}
	if len(store.credentials) != 0 || store.userRoles[prefix+"role"].Status != "revoked" || store.refreshTokens[prefix+"token"].RevokedAt == "" || len(store.externalAccounts) != 1 {
		t.Fatal("credentials, roles, sessions or binding policy incorrect")
	}
	visible, _ := store.ListIdentityUsersWithinDataScope(ctx, ws, scope)
	if len(visible) != 0 {
		t.Fatal("deleted user visible")
	}
	if _, _, err := store.ArchiveIdentityAccountWithinDataScope(ctx, ws, "user", 1, scope); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIdentityUserStatus(ctx, ws, "user", identitymodel.IdentityStatusActive); err == nil {
		t.Fatal("enable restored deleted account")
	}
	user.Status = identitymodel.IdentityStatusActive
	if err := store.UpsertIdentityUser(ctx, ws, user); err == nil {
		t.Fatal("upsert restored deleted account")
	}
}
