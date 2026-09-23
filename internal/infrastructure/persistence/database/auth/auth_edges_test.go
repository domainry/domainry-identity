package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestAuthMutationDecisionLifecycle(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStore(identity)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	request := authmodel.AuthMutationClaimRequest{
		Receipt:            authmodel.AuthMutationReceipt{WorkspaceID: "workspace-primary", UseCase: " reset ", TargetID: " user ", ActorID: " actor ", IdempotencyKey: " key "},
		RequestFingerprint: " fingerprint ",
		LeaseOwner:         " worker ",
		Now:                now,
		LeaseTTL:           time.Second,
	}
	if _, err := repository.TryBeginAuthMutation(t.Context(), "other", request); err == nil {
		t.Fatal("workspace mismatch accepted")
	}
	if _, err := repository.TryBeginAuthMutation(t.Context(), "workspace-primary", request); err == nil {
		t.Fatal("unbound shared Operations persistence accepted")
	}
	installAndBindAuthTestSharedOperations(t, identity)
	claim, err := repository.TryBeginAuthMutation(t.Context(), "workspace-primary", request)
	if err != nil || claim.Decision != idempotency.DecisionAcquired || claim.Receipt.UseCase != "reset" {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}
	inProgress, err := repository.TryBeginAuthMutation(t.Context(), "workspace-primary", request)
	if err != nil || inProgress.Decision != idempotency.DecisionInProgress {
		t.Fatalf("in-progress=%#v err=%v", inProgress, err)
	}
	conflictRequest := request
	conflictRequest.RequestFingerprint = "different"
	conflict, err := repository.TryBeginAuthMutation(t.Context(), "workspace-primary", conflictRequest)
	if err != nil || conflict.Decision != idempotency.DecisionFingerprintConflict {
		t.Fatalf("conflict=%#v err=%v", conflict, err)
	}
	reclaimedRequest := request
	reclaimedRequest.Now = now.Add(2 * time.Second)
	reclaimed, err := repository.TryBeginAuthMutation(t.Context(), "workspace-primary", reclaimedRequest)
	if err != nil || reclaimed.Decision != idempotency.DecisionAcquired || reclaimed.Receipt.FencingToken != 2 {
		t.Fatalf("reclaimed=%#v err=%v", reclaimed, err)
	}
	completed, err := repository.CompleteAuthMutation(t.Context(), "workspace-primary", authmodel.AuthMutationCompletion{
		ReceiptID: reclaimed.Receipt.ID, LeaseOwner: " worker ", FencingToken: reclaimed.Receipt.FencingToken,
		Failed: true, ErrorCode: " failed ", Result: map[string]any{"ok": false}, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil || completed.Status != string(idempotency.StatusFailedTerminal) || completed.ErrorCode != "failed" {
		t.Fatalf("completed=%#v err=%v", completed, err)
	}
	var operationCount, legacyTableCount int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _operations WHERE workspace_id='workspace-primary' AND owner='identity' AND kind='identity.auth_mutation' AND idempotency_key='key' AND status='failed' AND fencing_token=2`).Scan(&operationCount); err != nil || operationCount != 1 {
		t.Fatalf("shared auth mutation operation count=%d err=%v", operationCount, err)
	}
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_auth_mutation_receipts'`).Scan(&legacyTableCount); err != nil || legacyTableCount != 0 {
		t.Fatalf("legacy auth mutation receipt table count=%d err=%v", legacyTableCount, err)
	}
	replayed, err := repository.TryBeginAuthMutation(t.Context(), "workspace-primary", reclaimedRequest)
	if err != nil || replayed.Decision != idempotency.DecisionReplay {
		t.Fatalf("replayed=%#v err=%v", replayed, err)
	}
	if _, err := repository.CompleteAuthMutation(t.Context(), "workspace-primary", authmodel.AuthMutationCompletion{Result: make(chan int)}); err == nil {
		t.Fatal("unencodable result accepted")
	}
	defaultRequest := request
	defaultRequest.Receipt.IdempotencyKey = "default-time"
	defaultRequest.Now, defaultRequest.LeaseTTL = time.Time{}, 0
	if defaultClaim, err := repository.TryBeginAuthMutation(t.Context(), "workspace-primary", defaultRequest); err != nil || defaultClaim.Decision != idempotency.DecisionAcquired {
		t.Fatalf("default claim=%#v err=%v", defaultClaim, err)
	}
}

func TestAuthStoreDefaultAndValidationEdges(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStore(identity)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := repository.UpsertIdentityCredential(cancelled, "workspace-primary", identitymodel.IdentityCredential{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("credential cancellation=%v", err)
	}
	if err := repository.UpsertIdentityExternalAccount(cancelled, "workspace-primary", identitymodel.IdentityExternalAccount{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("external cancellation=%v", err)
	}
	if err := repository.UpsertIdentityMFAFactor(cancelled, "workspace-primary", identitymodel.IdentityMFAFactor{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("MFA cancellation=%v", err)
	}
	if err := repository.UpsertIdentityCredential(t.Context(), "workspace-primary", identitymodel.IdentityCredential{}); err == nil {
		t.Fatal("empty credential accepted")
	}
	if err := repository.UpsertIdentityCredential(t.Context(), "workspace-primary", identitymodel.IdentityCredential{UserID: "user"}); err == nil {
		t.Fatal("credential without password accepted")
	}
	if _, err := repository.ListIdentityMFAFactors(t.Context(), "workspace-primary", " "); err == nil {
		t.Fatal("MFA list without user accepted")
	}
	if err := repository.UpsertIdentityMFAFactor(t.Context(), "workspace-primary", identitymodel.IdentityMFAFactor{}); err == nil {
		t.Fatal("empty MFA factor accepted")
	}
	if err := repository.RevokeIdentityMFAFactor(t.Context(), "workspace-primary", "", "factor"); err == nil {
		t.Fatal("MFA revoke without user accepted")
	}
	if err := repository.RevokeIdentityMFAFactor(t.Context(), "workspace-primary", "user", ""); err == nil {
		t.Fatal("MFA revoke without factor accepted")
	}
	credential := identitymodel.IdentityCredential{UserID: "user", PasswordHash: "hash", LockedUntil: "locked", LastLoginAt: "last"}
	if err := repository.UpsertIdentityCredential(t.Context(), "workspace-primary", credential); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordIdentityLoginSuccess(t.Context(), "workspace-primary", credential.UserID, ""); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordIdentityLoginSuccess(t.Context(), "workspace-primary", credential.UserID, "fixed"); err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateAuthRefreshToken(t.Context(), "workspace-primary", identitymodel.AuthRefreshToken{}); err == nil {
		t.Fatal("empty token accepted")
	}
	for _, invalid := range []identitymodel.AuthRefreshToken{
		{ID: "id"},
		{ID: "id", UserID: "user"},
		{ID: "id", UserID: "user", SessionID: "session"},
		{ID: "id", UserID: "user", SessionID: "session", TokenHash: "hash"},
	} {
		if err := repository.CreateAuthRefreshToken(t.Context(), "workspace-primary", invalid); err == nil {
			t.Fatalf("incomplete token accepted: %#v", invalid)
		}
	}
	token := identitymodel.AuthRefreshToken{ID: "token", UserID: "user", SessionID: "session", TokenHash: "hash", ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}
	if err := repository.CreateAuthRefreshToken(t.Context(), "workspace-primary", token); err != nil {
		t.Fatal(err)
	}
	token.ID, token.TokenHash, token.CreatedAt = "token-fixed", "hash-fixed", "created"
	if err := repository.CreateAuthRefreshToken(t.Context(), "workspace-primary", token); err != nil {
		t.Fatal(err)
	}
	if _, found, err := repository.GetAuthRefreshTokenByHash(t.Context(), "workspace-primary", "missing"); err != nil || found {
		t.Fatalf("missing found=%v err=%v", found, err)
	}
	if err := repository.RevokeAuthRefreshToken(t.Context(), "workspace-primary", token.ID, "", "replacement"); err != nil {
		t.Fatal(err)
	}
	if count, err := repository.RevokeAuthRefreshTokensForUser(t.Context(), "workspace-primary", "user", ""); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if err := repository.UpsertIdentityExternalAccount(t.Context(), "workspace-primary", identitymodel.IdentityExternalAccount{}); err == nil {
		t.Fatal("empty external account accepted")
	}
	for _, invalid := range []identitymodel.IdentityExternalAccount{
		{ID: "id"},
		{ID: "id", UserID: "user"},
		{ID: "id", UserID: "user", Provider: "oidc"},
	} {
		if err := repository.UpsertIdentityExternalAccount(t.Context(), "workspace-primary", invalid); err == nil {
			t.Fatalf("incomplete account accepted: %#v", invalid)
		}
	}
	account := identitymodel.IdentityExternalAccount{ID: "account", UserID: "user", Provider: "oidc", ProviderSubject: "subject", Email: "e", Phone: "p", DisplayName: "d", AvatarURL: "a", Metadata: "m"}
	if err := repository.UpsertIdentityExternalAccount(t.Context(), "workspace-primary", account); err != nil {
		t.Fatal(err)
	}
	account.ID, account.ProviderSubject, account.LinkedAt = "account-fixed", "subject-fixed", "linked"
	if err := repository.UpsertIdentityExternalAccount(t.Context(), "workspace-primary", account); err != nil {
		t.Fatal(err)
	}
	accounts, err := repository.ListIdentityExternalAccounts(t.Context(), "workspace-primary", "")
	if err != nil || len(accounts) != 2 || accounts[0].Metadata != "m" {
		t.Fatalf("accounts=%#v err=%v", accounts, err)
	}
}
