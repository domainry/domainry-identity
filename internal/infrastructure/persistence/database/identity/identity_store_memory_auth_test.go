package identity

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestMemoryIdentityStoreCredentialLifecycle(t *testing.T) {
	store := NewMemoryIdentityStore()
	if _, found, err := store.getIdentityCredential("missing"); err != nil || found {
		t.Fatalf("missing credential found=%t err=%v", found, err)
	}
	if err := store.upsertIdentityCredential(identitymodel.IdentityCredential{}); err == nil {
		t.Fatal("expected missing user id error")
	}
	credential := identitymodel.IdentityCredential{UserID: "user-1", PasswordHash: "hash", FailedLoginCount: 2, LockedUntil: "later"}
	if err := store.upsertIdentityCredential(credential); err != nil {
		t.Fatalf("upsert credential: %v", err)
	}
	if got, found, err := store.getIdentityCredential("user-1"); err != nil || !found || got.PasswordHash != "hash" {
		t.Fatalf("credential=%#v found=%t err=%v", got, found, err)
	}
	if err := store.recordIdentityLoginFailure("user-1"); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	if err := store.recordIdentityLoginFailure("new-user"); err != nil {
		t.Fatalf("record new failure: %v", err)
	}
	got, _, _ := store.getIdentityCredential("user-1")
	if got.FailedLoginCount != 3 {
		t.Fatalf("failed login count=%d", got.FailedLoginCount)
	}
	if got, found, _ := store.getIdentityCredential("new-user"); !found || got.UserID != "new-user" || got.FailedLoginCount != 1 {
		t.Fatalf("new credential=%#v found=%t", got, found)
	}
	if err := store.recordIdentityLoginSuccess("user-1", "2026-07-19T12:00:00Z"); err != nil {
		t.Fatalf("record success: %v", err)
	}
	if err := store.recordIdentityLoginSuccess("success-only", "2026-07-19T12:01:00Z"); err != nil {
		t.Fatalf("record new success: %v", err)
	}
	got, _, _ = store.getIdentityCredential("user-1")
	if got.FailedLoginCount != 0 || got.LockedUntil != "" || got.LastLoginAt != "2026-07-19T12:00:00Z" {
		t.Fatalf("successful credential=%#v", got)
	}
}

func TestMemoryIdentityStoreRefreshTokenLifecycle(t *testing.T) {
	store := NewMemoryIdentityStore()
	invalid := []identitymodel.AuthRefreshToken{
		{TokenHash: "hash", UserID: "user-1"},
		{ID: "token-1", UserID: "user-1"},
		{ID: "token-1", TokenHash: "hash"},
	}
	for _, token := range invalid {
		if err := store.createAuthRefreshToken(token); err == nil {
			t.Fatalf("expected invalid token error for %#v", token)
		}
	}
	token := identitymodel.AuthRefreshToken{ID: "token-1", TokenHash: "hash-1", UserID: "user-1", SessionID: "session-1"}
	if err := store.createAuthRefreshToken(token); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	if got, found, err := store.getAuthRefreshTokenByHash("hash-1"); err != nil || !found || got.ID != token.ID {
		t.Fatalf("token=%#v found=%t err=%v", got, found, err)
	}
	if _, found, err := store.getAuthRefreshTokenByHash("missing"); err != nil || found {
		t.Fatalf("missing token found=%t err=%v", found, err)
	}
	if err := store.revokeAuthRefreshToken("missing", "now", "replacement"); err != nil {
		t.Fatalf("revoke missing token: %v", err)
	}
	if err := store.revokeAuthRefreshToken(token.ID, "2026-07-19T12:00:00Z", "token-2"); err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	got, _, _ := store.getAuthRefreshTokenByHash(token.TokenHash)
	if got.RevokedAt == "" || got.LastUsedAt != got.RevokedAt || got.ReplacedByID != "token-2" {
		t.Fatalf("revoked token=%#v", got)
	}
}

func TestMemoryIdentityStoreRefreshTokensForUser(t *testing.T) {
	store := NewMemoryIdentityStore()
	for _, token := range []identitymodel.AuthRefreshToken{
		{ID: "active-a", TokenHash: "hash-a", UserID: "user-a"},
		{ID: "revoked-a", TokenHash: "hash-revoked", UserID: "user-a", RevokedAt: "earlier"},
		{ID: "active-b", TokenHash: "hash-b", UserID: "user-b"},
	} {
		if err := store.createAuthRefreshToken(token); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := store.listAuthRefreshTokensForUser("user-a")
	if err != nil || len(tokens) != 2 {
		t.Fatalf("tokens=%#v err=%v", tokens, err)
	}
	count, err := store.revokeAuthRefreshTokensForUser("user-a", "2026-07-19T13:00:00Z")
	if err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	active, found, err := store.getAuthRefreshTokenByHash("hash-a")
	if err != nil || !found || active.RevokedAt != "2026-07-19T13:00:00Z" || active.LastUsedAt != active.RevokedAt {
		t.Fatalf("active=%#v found=%t err=%v", active, found, err)
	}
	alreadyRevoked, _, _ := store.getAuthRefreshTokenByHash("hash-revoked")
	if alreadyRevoked.RevokedAt != "earlier" {
		t.Fatalf("already revoked token changed=%#v", alreadyRevoked)
	}
	other, _, _ := store.getAuthRefreshTokenByHash("hash-b")
	if other.RevokedAt != "" {
		t.Fatalf("other user token changed=%#v", other)
	}
}

func TestMemoryIdentityStoreExternalAccountLifecycle(t *testing.T) {
	store := NewMemoryIdentityStore()
	invalid := []identitymodel.IdentityExternalAccount{
		{UserID: "user-1", Provider: "oidc", ProviderSubject: "subject"},
		{ID: "account-1", Provider: "oidc", ProviderSubject: "subject"},
		{ID: "account-1", UserID: "user-1", ProviderSubject: "subject"},
		{ID: "account-1", UserID: "user-1", Provider: "oidc"},
	}
	for _, account := range invalid {
		if err := store.upsertIdentityExternalAccount(account); err == nil {
			t.Fatalf("expected invalid account error for %#v", account)
		}
	}
	accounts := []identitymodel.IdentityExternalAccount{
		{ID: "account-3", UserID: "user-2", Provider: "saml", ProviderSubject: "z"},
		{ID: "account-2", UserID: "user-1", Provider: "oidc", ProviderSubject: "b"},
		{ID: "account-1", UserID: "user-1", Provider: "oidc", ProviderSubject: "a"},
	}
	for _, account := range accounts {
		if err := store.upsertIdentityExternalAccount(account); err != nil {
			t.Fatalf("upsert account: %v", err)
		}
	}
	all, err := store.listIdentityExternalAccounts("")
	if err != nil || len(all) != 3 || all[0].ID != "account-1" || all[1].ID != "account-2" || all[2].ID != "account-3" {
		t.Fatalf("all accounts=%#v err=%v", all, err)
	}
	filtered, err := store.listIdentityExternalAccounts("user-1")
	if err != nil || len(filtered) != 2 {
		t.Fatalf("filtered accounts=%#v err=%v", filtered, err)
	}
	accounts[1].DisplayName = "Updated"
	if err := store.upsertIdentityExternalAccount(accounts[1]); err != nil {
		t.Fatalf("update account: %v", err)
	}
	if err := store.removeIdentityExternalAccount("account-2"); err != nil {
		t.Fatalf("remove account: %v", err)
	}
	if err := store.removeIdentityExternalAccount("missing"); err != nil {
		t.Fatalf("remove missing account: %v", err)
	}
	filtered, _ = store.listIdentityExternalAccounts("user-1")
	if len(filtered) != 1 || filtered[0].ID != "account-1" {
		t.Fatalf("remaining accounts=%#v", filtered)
	}
}
