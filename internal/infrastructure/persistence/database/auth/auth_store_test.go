// Auth store tests.
package auth

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"

	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/mutation"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestAuthSessionStateRevocationConcurrencyAndRestartPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "session-revocation.db")
	open := func() (*database.IdentityStore, AuthStore) {
		store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: dbPath})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnsureIdentitySchema(t.Context()); err != nil {
			store.Close()
			t.Fatal(err)
		}
		identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		return store, NewAuthStore(identity)
	}
	store, repository := open()
	now := time.Now().UTC()
	tokens := []identitymodel.AuthRefreshToken{
		{ID: "current", UserID: "user", SessionID: "session-current", TokenHash: "current", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		{ID: "other-a", UserID: "user", SessionID: "session-other", TokenHash: "other-a", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		{ID: "other-b", UserID: "user", SessionID: "session-other", TokenHash: "other-b", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		{ID: "other-user", UserID: "other-user", SessionID: "session-foreign", TokenHash: "foreign", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		{ID: "expired", UserID: "user", SessionID: "session-expired", TokenHash: "expired", ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339)},
	}
	for _, token := range tokens {
		if err := repository.CreateAuthRefreshToken(t.Context(), "workspace-a", token); err != nil {
			store.Close()
			t.Fatal(err)
		}
	}
	if state, err := repository.AuthSessionState(t.Context(), "workspace-a", "user", "session-current", now); err != nil || state != authrepository.AuthSessionStateActive {
		store.Close()
		t.Fatalf("current state=%q err=%v", state, err)
	}
	counts := make(chan int, 2)
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			count, err := repository.RevokeOtherAuthSessions(t.Context(), "workspace-a", "user", "session-current", now.Format(time.RFC3339))
			counts <- count
			errs <- err
		}()
	}
	wait.Wait()
	close(counts)
	close(errs)
	total := 0
	for count := range counts {
		total += count
	}
	for err := range errs {
		if err != nil {
			store.Close()
			t.Fatalf("concurrent revoke error=%v", err)
		}
	}
	if total != 1 {
		store.Close()
		t.Fatalf("logical sessions revoked=%d, want 1", total)
	}
	if state, _ := repository.AuthSessionState(t.Context(), "workspace-a", "user", "session-current", now); state != authrepository.AuthSessionStateActive {
		store.Close()
		t.Fatalf("current session state=%q", state)
	}
	if state, _ := repository.AuthSessionState(t.Context(), "workspace-a", "user", "session-other", now); state != authrepository.AuthSessionStateRevoked {
		store.Close()
		t.Fatalf("other session state=%q", state)
	}
	store.Close()
	store, repository = open()
	defer store.Close()
	if state, _ := repository.AuthSessionState(t.Context(), "workspace-a", "user", "session-other", now); state != authrepository.AuthSessionStateRevoked {
		t.Fatalf("restarted revoked state=%q", state)
	}
	if state, _ := repository.AuthSessionState(t.Context(), "workspace-a", "other-user", "session-foreign", now); state != authrepository.AuthSessionStateActive {
		t.Fatalf("cross-user session state=%q", state)
	}
	if count, err := repository.RevokeAuthRefreshTokensForUser(t.Context(), "workspace-a", "user", now.Format(time.RFC3339)); err != nil || count != 1 {
		t.Fatalf("force logout count=%d err=%v", count, err)
	}
	if state, _ := repository.AuthSessionState(t.Context(), "workspace-a", "user", "session-current", now); state != authrepository.AuthSessionStateRevoked {
		t.Fatalf("force-logged-out state=%q", state)
	}
}

func TestRefreshTokenRotationIsAtomicUnderConcurrency(t *testing.T) {
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
	now := time.Now().UTC()
	old := identitymodel.AuthRefreshToken{ID: "old", UserID: "user", SessionID: "session", TokenHash: "old-hash", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if err := repository.CreateAuthRefreshToken(t.Context(), "default", old); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for index := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			replacement := identitymodel.AuthRefreshToken{ID: fmt.Sprintf("new-%d", index), UserID: "user", SessionID: "session", TokenHash: fmt.Sprintf("hash-%d", index), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
			rotated, rotateErr := repository.RotateAuthRefreshToken(t.Context(), "default", old.ID, now.Format(time.RFC3339), replacement)
			if rotateErr != nil {
				t.Errorf("rotate: %v", rotateErr)
				return
			}
			if rotated {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("atomic rotation successes=%d want 1", successes.Load())
	}
	tokens, err := repository.ListAuthRefreshTokensForUser(t.Context(), "default", "user")
	if err != nil || len(tokens) != 2 {
		t.Fatalf("tokens=%#v err=%v", tokens, err)
	}
}

func TestLoginFailureCounterIsAtomicUnderConcurrency(t *testing.T) {
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
	credential := identitymodel.IdentityCredential{UserID: "login-user", PasswordHash: "hash", PasswordUpdatedAt: "2026-08-17T00:00:00Z"}
	if err := repository.UpsertIdentityCredential(t.Context(), "default", credential); err != nil {
		t.Fatal(err)
	}
	const attempts = 16
	lockedUntil := "2026-08-17T01:00:00Z"
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := repository.RecordIdentityLoginFailure(t.Context(), "default", credential.UserID, 5, lockedUntil, "2026-08-17T00:00:01Z"); err != nil {
				t.Errorf("record login failure: %v", err)
			}
		}()
	}
	wait.Wait()
	loaded, found, err := repository.GetIdentityCredential(t.Context(), "default", credential.UserID)
	if err != nil || !found || loaded.FailedLoginCount != attempts || loaded.LockedUntil != lockedUntil {
		t.Fatalf("credential=%#v found=%v err=%v", loaded, found, err)
	}
}

func TestAuthMutationCompletionMapsOwnerAndFencingMismatchToLeaseLost(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStore(identity, store.IdempotencyMetrics(t.Context()))
	now := time.Date(2026, 7, 19, 18, 0, 0, 0, time.UTC)
	claim, err := repository.TryBeginAuthMutation(t.Context(), "workspace-a", authmodel.AuthMutationClaimRequest{Receipt: authmodel.AuthMutationReceipt{WorkspaceID: "workspace-a", UseCase: "auth.password_reset", TargetID: "user-a", IdempotencyKey: "reset-a"}, RequestFingerprint: "fingerprint", LeaseOwner: "runtime-a", LeaseTTL: time.Minute, Now: now})
	if err != nil || claim.Decision != idempotency.DecisionAcquired {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}
	_, err = repository.CompleteAuthMutation(t.Context(), "workspace-a", authmodel.AuthMutationCompletion{ReceiptID: claim.Receipt.ID, LeaseOwner: "runtime-b", FencingToken: claim.Receipt.FencingToken, Result: true, ExpiresAt: now.Add(time.Hour), Now: now})
	if !mutation.IsMutationConflict(err, mutation.MutationConflictLeaseLost) {
		t.Fatalf("wrong owner error=%v", err)
	}
}

func TestAuthStoreContractAndCancellation(t *testing.T) {
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
	credential := identitymodel.IdentityCredential{UserID: "auth-user", PasswordHash: "hash", PasswordUpdatedAt: "2026-07-12T00:00:00Z"}
	if err := repository.UpsertIdentityCredential(t.Context(), "default", credential); err != nil {
		t.Fatalf("upsert credential: %v", err)
	}
	loaded, found, err := repository.GetIdentityCredential(t.Context(), "default", credential.UserID)
	if err != nil || !found || loaded.PasswordHash != credential.PasswordHash {
		t.Fatalf("credential=%#v found=%v err=%v", loaded, found, err)
	}
	token := identitymodel.AuthRefreshToken{ID: "refresh-context", UserID: credential.UserID, SessionID: "session-context", TokenHash: "token-context", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := repository.CreateAuthRefreshToken(t.Context(), "default", token); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	if tokens, err := repository.ListAuthRefreshTokensForUser(t.Context(), "default", credential.UserID); err != nil || len(tokens) != 1 {
		t.Fatalf("tokens=%#v err=%v", tokens, err)
	}
	account := identitymodel.IdentityExternalAccount{ID: "external-context", UserID: credential.UserID, Provider: "oidc", ProviderSubject: "subject-context"}
	if err := repository.UpsertIdentityExternalAccount(t.Context(), "default", account); err != nil {
		t.Fatalf("upsert external account: %v", err)
	}
	if accounts, err := repository.ListIdentityExternalAccounts(t.Context(), "default", credential.UserID); err != nil || len(accounts) != 1 {
		t.Fatalf("accounts=%#v err=%v", accounts, err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := repository.GetIdentityCredential(cancelled, "default", credential.UserID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled credential query error=%v", err)
	}
	if err := repository.CreateAuthRefreshToken(cancelled, "default", identitymodel.AuthRefreshToken{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled token insert error=%v", err)
	}
}

func TestAuthStoreWorkspaceIsolationContract(t *testing.T) {
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

	credentialA := identitymodel.IdentityCredential{UserID: "auth-user-a", PasswordHash: "hash-a", PasswordUpdatedAt: "2026-07-19T00:00:00Z"}
	credentialB := identitymodel.IdentityCredential{UserID: "auth-user-b", PasswordHash: "hash-b", PasswordUpdatedAt: "2026-07-19T00:00:00Z"}
	if err := repository.UpsertIdentityCredential(t.Context(), "workspace-a", credentialA); err != nil {
		t.Fatalf("upsert workspace A credential: %v", err)
	}
	if err := repository.UpsertIdentityCredential(t.Context(), "workspace-b", credentialB); err != nil {
		t.Fatalf("upsert workspace B credential: %v", err)
	}
	if _, found, err := repository.GetIdentityCredential(t.Context(), "workspace-b", credentialA.UserID); err != nil || found {
		t.Fatalf("workspace B observed workspace A credential: found=%v err=%v", found, err)
	}

	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	tokenA := identitymodel.AuthRefreshToken{ID: "refresh-a", UserID: credentialA.UserID, SessionID: "session-a", TokenHash: "shared-token-hash", ExpiresAt: expiresAt}
	tokenB := identitymodel.AuthRefreshToken{ID: "refresh-b", UserID: credentialB.UserID, SessionID: "session-b", TokenHash: "shared-token-hash", ExpiresAt: expiresAt}
	if err := repository.CreateAuthRefreshToken(t.Context(), "workspace-a", tokenA); err != nil {
		t.Fatalf("create workspace A token: %v", err)
	}
	if err := repository.CreateAuthRefreshToken(t.Context(), "workspace-b", tokenB); err != nil {
		t.Fatalf("create workspace B token: %v", err)
	}
	loadedA, found, err := repository.GetAuthRefreshTokenByHash(t.Context(), "workspace-a", tokenA.TokenHash)
	if err != nil || !found || loadedA.ID != tokenA.ID {
		t.Fatalf("workspace A token=%#v found=%v err=%v", loadedA, found, err)
	}
	loadedB, found, err := repository.GetAuthRefreshTokenByHash(t.Context(), "workspace-b", tokenB.TokenHash)
	if err != nil || !found || loadedB.ID != tokenB.ID {
		t.Fatalf("workspace B token=%#v found=%v err=%v", loadedB, found, err)
	}
	if err := repository.RevokeAuthRefreshToken(t.Context(), "workspace-b", tokenA.ID, "2026-07-19T01:00:00Z", ""); err != nil {
		t.Fatalf("cross-workspace revoke: %v", err)
	}
	loadedA, found, err = repository.GetAuthRefreshTokenByHash(t.Context(), "workspace-a", tokenA.TokenHash)
	if err != nil || !found || loadedA.RevokedAt != "" {
		t.Fatalf("cross-workspace revoke changed workspace A token: %#v found=%v err=%v", loadedA, found, err)
	}

	accountA := identitymodel.IdentityExternalAccount{ID: "external-a", UserID: credentialA.UserID, Provider: "oidc", ProviderSubject: "shared-subject"}
	accountB := identitymodel.IdentityExternalAccount{ID: "external-b", UserID: credentialB.UserID, Provider: "oidc", ProviderSubject: "shared-subject"}
	if err := repository.UpsertIdentityExternalAccount(t.Context(), "workspace-a", accountA); err != nil {
		t.Fatalf("upsert workspace A account: %v", err)
	}
	if err := repository.UpsertIdentityExternalAccount(t.Context(), "workspace-b", accountB); err != nil {
		t.Fatalf("upsert workspace B account: %v", err)
	}
	accountsA, err := repository.ListIdentityExternalAccounts(t.Context(), "workspace-a", "")
	if err != nil || len(accountsA) != 1 || accountsA[0].ID != accountA.ID {
		t.Fatalf("workspace A accounts=%#v err=%v", accountsA, err)
	}
	if err := repository.RemoveIdentityExternalAccount(t.Context(), "workspace-b", accountA.ID); err != nil {
		t.Fatalf("cross-workspace account removal: %v", err)
	}
	accountsA, err = repository.ListIdentityExternalAccounts(t.Context(), "workspace-a", credentialA.UserID)
	if err != nil || len(accountsA) != 1 || accountsA[0].ID != accountA.ID {
		t.Fatalf("cross-workspace removal changed workspace A account: %#v err=%v", accountsA, err)
	}
}

func TestAuthStoreMFAFactorLifecycleAndWorkspaceIsolation(t *testing.T) {
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
	factor := identitymodel.IdentityMFAFactor{
		ID: "factor-a", UserID: "user-a", Type: "webauthn", Label: "Security key",
		Provider: "oidc", ProviderRef: "provider-factor-a", Status: "active",
		VerifiedAt: "2026-07-25T00:00:00Z", LastUsedAt: "2026-07-25T01:00:00Z",
	}
	if err := repository.UpsertIdentityMFAFactor(t.Context(), "workspace-a", factor); err != nil {
		t.Fatal(err)
	}
	factors, err := repository.ListIdentityMFAFactors(t.Context(), "workspace-a", "user-a")
	if err != nil || len(factors) != 1 || factors[0].ProviderRef != factor.ProviderRef || factors[0].CreatedAt == "" || factors[0].UpdatedAt == "" {
		t.Fatalf("factors=%#v err=%v", factors, err)
	}
	if other, err := repository.ListIdentityMFAFactors(t.Context(), "workspace-b", "user-a"); err != nil || len(other) != 0 {
		t.Fatalf("cross-workspace factors=%#v err=%v", other, err)
	}
	factor.Label, factor.CreatedAt = "Renamed key", factors[0].CreatedAt
	if err := repository.UpsertIdentityMFAFactor(t.Context(), "workspace-a", factor); err != nil {
		t.Fatal(err)
	}
	factors, err = repository.ListIdentityMFAFactors(t.Context(), "workspace-a", "user-a")
	if err != nil || len(factors) != 1 || factors[0].Label != "Renamed key" {
		t.Fatalf("updated factors=%#v err=%v", factors, err)
	}
	if err := repository.RevokeIdentityMFAFactor(t.Context(), "workspace-b", "user-a", factor.ID); err == nil {
		t.Fatal("cross-workspace factor revoke succeeded")
	}
	if err := repository.RevokeIdentityMFAFactor(t.Context(), "workspace-a", "user-a", factor.ID); err != nil {
		t.Fatal(err)
	}
	factors, err = repository.ListIdentityMFAFactors(t.Context(), "workspace-a", "user-a")
	if err != nil || len(factors) != 1 || factors[0].Status != "disabled" {
		t.Fatalf("revoked factors=%#v err=%v", factors, err)
	}
}

func TestAuthStoreRejectsMissingWorkspaceContract(t *testing.T) {
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
	now := time.Now().UTC()
	checks := []struct {
		name string
		call func() error
	}{
		{"get credential", func() error { _, _, err := repository.GetIdentityCredential(t.Context(), "", "user"); return err }},
		{"upsert credential", func() error {
			return repository.UpsertIdentityCredential(t.Context(), "", identitymodel.IdentityCredential{})
		}},
		{"record login", func() error { return repository.RecordIdentityLoginSuccess(t.Context(), "", "user", "") }},
		{"create refresh token", func() error {
			return repository.CreateAuthRefreshToken(t.Context(), "", identitymodel.AuthRefreshToken{})
		}},
		{"get refresh token", func() error { _, _, err := repository.GetAuthRefreshTokenByHash(t.Context(), "", "hash"); return err }},
		{"revoke refresh token", func() error { return repository.RevokeAuthRefreshToken(t.Context(), "", "token", "", "") }},
		{"list refresh tokens", func() error { _, err := repository.ListAuthRefreshTokensForUser(t.Context(), "", "user"); return err }},
		{"revoke user refresh tokens", func() error {
			_, err := repository.RevokeAuthRefreshTokensForUser(t.Context(), "", "user", "")
			return err
		}},
		{"list external accounts", func() error { _, err := repository.ListIdentityExternalAccounts(t.Context(), "", "user"); return err }},
		{"upsert external account", func() error {
			return repository.UpsertIdentityExternalAccount(t.Context(), "", identitymodel.IdentityExternalAccount{})
		}},
		{"remove external account", func() error { return repository.RemoveIdentityExternalAccount(t.Context(), "", "account") }},
		{"list MFA factors", func() error { _, err := repository.ListIdentityMFAFactors(t.Context(), "", "user"); return err }},
		{"upsert MFA factor", func() error {
			return repository.UpsertIdentityMFAFactor(t.Context(), "", identitymodel.IdentityMFAFactor{})
		}},
		{"revoke MFA factor", func() error { return repository.RevokeIdentityMFAFactor(t.Context(), "", "user", "factor") }},
		{"begin mutation", func() error {
			_, err := repository.TryBeginAuthMutation(t.Context(), "", authmodel.AuthMutationClaimRequest{})
			return err
		}},
		{"complete mutation", func() error {
			_, err := repository.CompleteAuthMutation(t.Context(), "", authmodel.AuthMutationCompletion{Now: now})
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.call(); err == nil {
				t.Fatal("missing workspace was accepted")
			}
		})
	}
}

func openStoreForGeneratedListTest(t *testing.T) *database.IdentityStore {
	t.Helper()
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "auth.db")})
	if err != nil {
		t.Fatal(err)
	}
	return store
}
