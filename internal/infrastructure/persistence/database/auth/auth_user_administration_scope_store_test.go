package auth

import (
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestAuthUserAdministrationMutationsEnforcePersistedUserDataScope(t *testing.T) {
	databaseStore := openStoreForGeneratedListTest(t)
	defer databaseStore.Close()
	if err := databaseStore.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), databaseStore.DB(), databaseStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	const workspaceID = "workspace-primary"
	users := []identitymodel.IdentityUser{
		{ID: "actor", Name: "Actor", Email: "actor@example.com", OrgID: "sales", Status: identitymodel.IdentityStatusActive},
		{ID: "sales-peer", Name: "Sales Peer", Email: "sales@example.com", OrgID: "sales", Status: identitymodel.IdentityStatusActive},
		{ID: "finance-peer", Name: "Finance Peer", Email: "finance@example.com", OrgID: "finance", Status: identitymodel.IdentityStatusActive},
	}
	for _, user := range users {
		if err := identityStore.UpsertIdentityUser(t.Context(), workspaceID, user); err != nil {
			t.Fatal(err)
		}
	}
	repository := NewAuthStore(identityStore)
	for _, user := range users {
		if err := repository.UpsertIdentityCredential(t.Context(), workspaceID, identitymodel.IdentityCredential{UserID: user.ID, PasswordHash: "hash", PasswordUpdatedAt: "2026-09-03T00:00:00Z", FailedLoginCount: 3, LockedUntil: "2026-09-04T00:00:00Z"}); err != nil {
			t.Fatal(err)
		}
	}

	owner := identitymodel.IdentityDataScopeFilter{OwnerUserIDs: []string{"actor"}}
	if visible, err := repository.IdentityUserExistsWithinDataScope(t.Context(), workspaceID, "actor", owner); err != nil || !visible {
		t.Fatalf("owner target visible=%t err=%v", visible, err)
	}
	if visible, err := repository.IdentityUserExistsWithinDataScope(t.Context(), workspaceID, "sales-peer", owner); err != nil || visible {
		t.Fatalf("foreign owner visible=%t err=%v", visible, err)
	}
	if visible, found, err := repository.UnlockIdentityCredentialWithinDataScope(t.Context(), workspaceID, "finance-peer", identitymodel.IdentityDataScopeFilter{OwnerOrgIDs: []string{"sales"}}); err != nil || visible || found {
		t.Fatalf("out-of-org unlock visible=%t found=%t err=%v", visible, found, err)
	}
	locked, found, err := repository.GetIdentityCredential(t.Context(), workspaceID, "finance-peer")
	if err != nil || !found || locked.FailedLoginCount != 3 || locked.LockedUntil == "" {
		t.Fatalf("denied unlock changed credential=%#v found=%t err=%v", locked, found, err)
	}
	if visible, found, err := repository.UnlockIdentityCredentialWithinDataScope(t.Context(), workspaceID, "sales-peer", identitymodel.IdentityDataScopeFilter{OwnerOrgIDs: []string{"sales"}}); err != nil || !visible || !found {
		t.Fatalf("in-org unlock visible=%t found=%t err=%v", visible, found, err)
	}
	unlocked, found, err := repository.GetIdentityCredential(t.Context(), workspaceID, "sales-peer")
	if err != nil || !found || unlocked.FailedLoginCount != 0 || unlocked.LockedUntil != "" {
		t.Fatalf("unlocked credential=%#v found=%t err=%v", unlocked, found, err)
	}
	orgScope := identitymodel.IdentityDataScopeFilter{OwnerOrgIDs: []string{"sales"}}
	if updated, err := repository.ResetIdentityCredentialWithinDataScope(t.Context(), workspaceID, "finance-peer", "denied-hash", "2026-09-03T01:00:00Z", true, orgScope); err != nil || updated {
		t.Fatalf("out-of-org password reset updated=%t err=%v", updated, err)
	}
	financeCredential, found, err := repository.GetIdentityCredential(t.Context(), workspaceID, "finance-peer")
	if err != nil || !found || financeCredential.PasswordHash != "hash" {
		t.Fatalf("denied password reset credential=%#v found=%t err=%v", financeCredential, found, err)
	}
	if updated, err := repository.ResetIdentityCredentialWithinDataScope(t.Context(), workspaceID, "sales-peer", "replacement-hash", "2026-09-03T01:00:00Z", true, orgScope); err != nil || !updated {
		t.Fatalf("in-org password reset updated=%t err=%v", updated, err)
	}
	resetCredential, found, err := repository.GetIdentityCredential(t.Context(), workspaceID, "sales-peer")
	if err != nil || !found || resetCredential.PasswordHash != "replacement-hash" || !resetCredential.MustChangePassword {
		t.Fatalf("reset credential=%#v found=%t err=%v", resetCredential, found, err)
	}

	if err := repository.UpsertIdentityMFAFactor(t.Context(), workspaceID, identitymodel.IdentityMFAFactor{ID: "finance-factor", UserID: "finance-peer", Type: "totp", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if visible, found, err := repository.RevokeIdentityMFAFactorWithinDataScope(t.Context(), workspaceID, "finance-peer", "finance-factor", identitymodel.IdentityDataScopeFilter{OwnerOrgIDs: []string{"sales"}}); err != nil || visible || found {
		t.Fatalf("out-of-org MFA revoke visible=%t found=%t err=%v", visible, found, err)
	}
	factors, err := repository.ListIdentityMFAFactors(t.Context(), workspaceID, "finance-peer")
	if err != nil || len(factors) != 1 || factors[0].Status != "active" {
		t.Fatalf("denied MFA revoke factors=%#v err=%v", factors, err)
	}

	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	for _, token := range []identitymodel.AuthRefreshToken{
		{ID: "sales-token", UserID: "sales-peer", SessionID: "sales-session", TokenHash: "sales-hash", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		{ID: "finance-token", UserID: "finance-peer", SessionID: "finance-session", TokenHash: "finance-hash", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
	} {
		if err := repository.CreateAuthRefreshToken(t.Context(), workspaceID, token); err != nil {
			t.Fatal(err)
		}
	}
	if count, visible, err := repository.RevokeAuthRefreshTokensForUserWithinDataScope(t.Context(), workspaceID, "finance-peer", now.Format(time.RFC3339), orgScope); err != nil || visible || count != 0 {
		t.Fatalf("out-of-org force logout count=%d visible=%t err=%v", count, visible, err)
	}
	if count, visible, err := repository.RevokeAuthRefreshTokensForUserWithinDataScope(t.Context(), workspaceID, "sales-peer", now.Format(time.RFC3339), orgScope); err != nil || !visible || count != 1 {
		t.Fatalf("in-org force logout count=%d visible=%t err=%v", count, visible, err)
	}
	financeTokens, err := repository.ListAuthRefreshTokensForUser(t.Context(), workspaceID, "finance-peer")
	if err != nil || len(financeTokens) != 1 || financeTokens[0].RevokedAt != "" {
		t.Fatalf("denied force logout tokens=%#v err=%v", financeTokens, err)
	}
}
