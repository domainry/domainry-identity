package auth

import (
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestOTPTransactionPersistsAttemptsAndConsumesExactlyOnce(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStoreWithKeyProvider(identityStore, store.SecretKeyProvider())
	now := time.Now().UTC()
	challenge := authmodel.AuthProviderChallenge{WorkspaceID: "workspace-primary", Provider: "otp", State: "otp-state", Phone: "10000000000", Code: "123456", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	created, err := repository.CreateAuthOTPTransaction(t.Context(), challenge, "phone-key", now.Add(time.Minute), now)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	wrong, valid, err := repository.ConsumeAuthOTPTransaction(t.Context(), "workspace-primary", "otp", challenge.State, "000000", []string{authmodel.AuthChallengePurposeLogin}, "", 3, now)
	if err != nil || valid || wrong.Attempts != 1 {
		t.Fatalf("wrong=%#v valid=%v err=%v", wrong, valid, err)
	}
	accepted, valid, err := repository.ConsumeAuthOTPTransaction(t.Context(), "workspace-primary", "otp", challenge.State, challenge.Code, []string{authmodel.AuthChallengePurposeLogin}, "", 3, now)
	if err != nil || !valid || accepted.Phone != challenge.Phone {
		t.Fatalf("accepted=%#v valid=%v err=%v", accepted, valid, err)
	}
	if replay, valid, err := repository.ConsumeAuthOTPTransaction(t.Context(), "workspace-primary", "otp", challenge.State, challenge.Code, []string{authmodel.AuthChallengePurposeLogin}, "", 3, now); err != nil || valid || replay.State != "" {
		t.Fatalf("replay=%#v valid=%v err=%v", replay, valid, err)
	}
}

func TestOTPTransactionEnforcesDeliveryCooldownAcrossRequests(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStoreWithKeyProvider(identityStore, store.SecretKeyProvider())
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	challenge := func(state string) authmodel.AuthProviderChallenge {
		return authmodel.AuthProviderChallenge{WorkspaceID: "workspace-primary", Provider: "otp", State: state, Phone: "10000000000", Code: "123456", ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano), CreatedAt: now.Format(time.RFC3339Nano)}
	}
	created, err := repository.CreateAuthOTPTransaction(t.Context(), challenge("first"), "same-phone", now.Add(time.Minute), now)
	if err != nil || !created {
		t.Fatalf("first created=%v err=%v", created, err)
	}
	created, err = repository.CreateAuthOTPTransaction(t.Context(), challenge("blocked"), "same-phone", now.Add(90*time.Second), now.Add(30*time.Second))
	if err != nil || created {
		t.Fatalf("cooldown created=%v err=%v", created, err)
	}
	created, err = repository.CreateAuthOTPTransaction(t.Context(), challenge("next"), "same-phone", now.Add(2*time.Minute), now.Add(time.Minute))
	if err != nil || !created {
		t.Fatalf("next created=%v err=%v", created, err)
	}
}

func TestOTPDeliveryClaimDoesNotDependOnConflictRowsAffected(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStoreWithKeyProvider(identityStore, store.SecretKeyProvider())
	now := time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)
	challenge := func(state string) authmodel.AuthProviderChallenge {
		return authmodel.AuthProviderChallenge{
			WorkspaceID: "workspace-primary", Provider: "email_credential", Purpose: "password_recovery",
			State: state, Email: "owner@example.test", Code: "123456",
			CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		}
	}
	created, err := repository.CreateAuthOTPTransaction(t.Context(), challenge("first-state"), "same-recovery-email", now.Add(time.Minute), now)
	if err != nil || !created {
		t.Fatalf("first claim created=%v err=%v", created, err)
	}
	created, err = repository.CreateAuthOTPTransaction(t.Context(), challenge("second-state"), "same-recovery-email", now.Add(time.Minute), now)
	if err != nil || created {
		t.Fatalf("duplicate claim created=%v err=%v", created, err)
	}
	var transactions int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_auth_login_transactions WHERE subject_key_hash = ?`, "same-recovery-email").Scan(&transactions); err != nil {
		t.Fatal(err)
	}
	if transactions != 1 {
		t.Fatalf("duplicate cooldown claim persisted %d challenges", transactions)
	}
}

func TestOTPTransactionPurposeAndSubjectMismatchDoesNotConsumeChallenge(t *testing.T) {
	store := openStoreForGeneratedListTest(t)
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewAuthStoreWithKeyProvider(identityStore, store.SecretKeyProvider())
	now := time.Now().UTC()
	challenge := authmodel.AuthProviderChallenge{
		WorkspaceID: "workspace-primary", Provider: "otp", State: "action-state", Phone: "+10000000000", Code: "123456",
		Purpose: authmodel.AuthChallengePurposeAction, UserID: "user-a", Status: authmodel.AuthChallengeStatusActive,
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	created, err := repository.CreateAuthOTPTransaction(t.Context(), challenge, "action-user-key", now.Add(time.Minute), now)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if rejected, valid, err := repository.ConsumeAuthOTPTransaction(t.Context(), "workspace-primary", "otp", challenge.State, challenge.Code, []string{authmodel.AuthChallengePurposeLogin}, "", 3, now); err != nil || valid || rejected.State != "" {
		t.Fatalf("login mismatch challenge=%#v valid=%v err=%v", rejected, valid, err)
	}
	if rejected, valid, err := repository.ConsumeAuthOTPTransaction(t.Context(), "workspace-primary", "otp", challenge.State, challenge.Code, []string{authmodel.AuthChallengePurposeAction}, "user-b", 3, now); err != nil || valid || rejected.State != "" {
		t.Fatalf("subject mismatch challenge=%#v valid=%v err=%v", rejected, valid, err)
	}
	accepted, valid, err := repository.ConsumeAuthOTPTransaction(t.Context(), "workspace-primary", "otp", challenge.State, challenge.Code, []string{authmodel.AuthChallengePurposeAction}, "user-a", 3, now)
	if err != nil || !valid || accepted.UserID != "user-a" || accepted.Purpose != authmodel.AuthChallengePurposeAction {
		t.Fatalf("accepted=%#v valid=%v err=%v", accepted, valid, err)
	}
}
