package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-orm/query"
)

func newTOTPRepository(t *testing.T) AuthStore {
	t.Helper()
	store := openStoreForGeneratedListTest(t)
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identities, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	return NewAuthStoreWithKeyProvider(identities, store.SecretKeyProvider())
}
func totpChallenge(state, purpose string, now time.Time) authmodel.AuthProviderChallenge {
	return authmodel.AuthProviderChallenge{WorkspaceID: "workspace-primary", UserID: "totp-user", Provider: authmodel.TOTPProvider, Type: "totp", Purpose: purpose, State: state, RequestID: "enrollment-generation", Status: authmodel.AuthChallengeStatusActive, ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339)}
}
func enrollTOTP(t *testing.T, repository AuthStore, now time.Time) {
	t.Helper()
	if err := repository.CreateTOTPEnrollment(t.Context(), totpChallenge("enroll", authmodel.TOTPEnrollmentPurpose, now), authmodel.TOTPSecret{Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}); err != nil {
		t.Fatal(err)
	}
}
func consumeTOTP(ctx context.Context, repository AuthStore, state, purpose, code string, now time.Time) (authmodel.AuthProviderChallenge, bool, error) {
	return repository.ConsumeAuthOTPTransaction(ctx, "workspace-primary", authmodel.TOTPProvider, state, code, []string{purpose}, "totp-user", 3, now)
}

func TestTOTPEnrollmentEncryptionPurposeScopeReplayAndDisable(t *testing.T) {
	repository := newTOTPRepository(t)
	now := time.Unix(1111111109, 0).UTC()
	enrollTOTP(t, repository, now)
	state, err := repository.TOTPFactorState(t.Context(), "workspace-primary", "totp-user")
	if err != nil || state.Enabled {
		t.Fatalf("pending enrollment enabled: %+v %v", state, err)
	}
	statement, args, err := query.NewWorkspaceSelectBuilder(repository.store.SQLRenderer(), "_identity_mfa_factors", "workspace-primary").Columns("totp_secret").Where(query.Equal("id", totpFactorID("workspace-primary", "totp-user"))).Build()
	if err != nil {
		t.Fatal(err)
	}
	var envelope string
	if err := repository.db.QueryRowContext(t.Context(), statement, args...).Scan(&envelope); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(envelope, "GEZDGNBV") || strings.Contains(envelope, "12345678901234567890") {
		t.Fatal("TOTP key is not encrypted")
	}
	if _, valid, err := consumeTOTP(t.Context(), repository, "enroll", authmodel.AuthChallengePurposeLoginMFA, "081804", now); err != nil || valid {
		t.Fatal("enrollment accepted by login")
	}
	if _, valid, err := repository.ConsumeAuthOTPTransaction(t.Context(), "workspace-other", authmodel.TOTPProvider, "enroll", "081804", []string{authmodel.TOTPEnrollmentPurpose}, "totp-user", 3, now); err != nil || valid {
		t.Fatal("cross-workspace enrollment accepted")
	}
	if _, valid, err := repository.ConsumeAuthOTPTransaction(t.Context(), "workspace-primary", authmodel.TOTPProvider, "enroll", "081804", []string{authmodel.TOTPEnrollmentPurpose}, "other-user", 3, now); err != nil || valid {
		t.Fatal("cross-user enrollment accepted")
	}
	if _, valid, err := consumeTOTP(t.Context(), repository, "enroll", authmodel.TOTPEnrollmentPurpose, "081804", now); err != nil || !valid {
		t.Fatalf("confirmation failed: valid=%v err=%v", valid, err)
	}
	state, err = repository.TOTPFactorState(t.Context(), "workspace-primary", "totp-user")
	if err != nil || !state.Enabled {
		t.Fatalf("confirmed factor unavailable: %+v %v", state, err)
	}
	if err := repository.CreateTOTPEnrollment(t.Context(), totpChallenge("replace", authmodel.TOTPEnrollmentPurpose, now), authmodel.TOTPSecret{Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}); err == nil {
		t.Fatal("active factor replaced without verification")
	}
	for _, id := range []string{"action-one", "action-two"} {
		if err := repository.CreateAuthLoginTransaction(t.Context(), totpChallenge(id, authmodel.AuthChallengePurposeAction, now)); err != nil {
			t.Fatal(err)
		}
	}
	if _, valid, err := consumeTOTP(t.Context(), repository, "action-one", authmodel.AuthChallengePurposeAction, "081804", now); err != nil || valid {
		t.Fatal("enrollment code reused for action")
	}
	next := time.Unix(1111111111, 0).UTC()
	if _, valid, err := consumeTOTP(t.Context(), repository, "action-one", authmodel.AuthChallengePurposeAction, "050471", next); err != nil || !valid {
		t.Fatalf("next step rejected: %v", err)
	}
	if _, valid, err := consumeTOTP(t.Context(), repository, "action-two", authmodel.AuthChallengePurposeAction, "050471", next); err != nil || valid {
		t.Fatal("same step reused on another challenge")
	}
	// Administrative revocation immediately invalidates outstanding challenges.
	if err := repository.RevokeIdentityMFAFactor(t.Context(), "workspace-primary", "totp-user", totpFactorID("workspace-primary", "totp-user")); err != nil {
		t.Fatal(err)
	}
	state, err = repository.TOTPFactorState(t.Context(), "workspace-primary", "totp-user")
	if err != nil || state.Enabled {
		t.Fatal("revocation did not take effect")
	}
}

func TestTOTPFailuresSurviveNewChallengesAndPendingReplacement(t *testing.T) {
	repository := newTOTPRepository(t)
	now := time.Unix(1111111109, 0).UTC()
	enrollTOTP(t, repository, now)
	for _, id := range []string{"wrong-a", "wrong-b", "wrong-c"} {
		if err := repository.CreateAuthLoginTransaction(t.Context(), totpChallenge(id, authmodel.TOTPEnrollmentPurpose, now)); err != nil {
			t.Fatal(err)
		}
		if _, valid, err := consumeTOTP(t.Context(), repository, id, authmodel.TOTPEnrollmentPurpose, "999999", now); err != nil || valid {
			t.Fatalf("failure: %v", err)
		}
	}
	// Starting binding again must preserve the factor's lockout budget.
	replacement := totpChallenge("enroll-again", authmodel.TOTPEnrollmentPurpose, now)
	if err := repository.CreateTOTPEnrollment(t.Context(), replacement, authmodel.TOTPSecret{Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}); err != nil {
		t.Fatal(err)
	}
	if _, valid, err := consumeTOTP(t.Context(), repository, "enroll-again", authmodel.TOTPEnrollmentPurpose, "081804", now); err != nil || valid {
		t.Fatal("new enrollment bypassed factor lockout")
	}
}
