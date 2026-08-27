package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type userAdministrationAuthRepository struct {
	*faultExternalAuthRepository
	listSessionsErr error
	revokeUserErr   error
	listMFAErr      error
	upsertMFAErr    error
	revokeMFAErr    error
	revokedUserID   string
	revokedAt       string
	revokedFactorID string
	mfaFactors      []identitymodel.IdentityMFAFactor
}

type authRepositoryWithoutMFA struct{ authrepository.AuthRepository }

func (r *userAdministrationAuthRepository) ListAuthRefreshTokensForUser(context.Context, string, string) ([]identitymodel.AuthRefreshToken, error) {
	if r.listSessionsErr != nil {
		return nil, r.listSessionsErr
	}
	return append([]identitymodel.AuthRefreshToken(nil), r.refreshTokens...), nil
}

func (r *userAdministrationAuthRepository) RevokeAuthRefreshTokensForUser(_ context.Context, _, userID, revokedAt string) (int, error) {
	if r.revokeUserErr != nil {
		return 0, r.revokeUserErr
	}
	r.revokedUserID = userID
	r.revokedAt = revokedAt
	return len(r.refreshTokens), nil
}

func (r *userAdministrationAuthRepository) ListIdentityMFAFactors(context.Context, string, string) ([]identitymodel.IdentityMFAFactor, error) {
	if r.listMFAErr != nil {
		return nil, r.listMFAErr
	}
	return append([]identitymodel.IdentityMFAFactor{}, r.mfaFactors...), nil
}

func (r *userAdministrationAuthRepository) UpsertIdentityMFAFactor(_ context.Context, _ string, factor identitymodel.IdentityMFAFactor) error {
	if r.upsertMFAErr != nil {
		return r.upsertMFAErr
	}
	r.mfaFactors = append(r.mfaFactors, factor)
	return nil
}

func (r *userAdministrationAuthRepository) RevokeIdentityMFAFactor(_ context.Context, _ string, userID, factorID string) error {
	if r.revokeMFAErr != nil {
		return r.revokeMFAErr
	}
	r.revokedUserID, r.revokedFactorID = userID, factorID
	return nil
}

func newUserAdministrationFixture() (*AuthDomainService, *faultExternalIdentityRepository, *userAdministrationAuthRepository) {
	auth, identities, baseRepository := newFaultAuthDomainService()
	repository := &userAdministrationAuthRepository{faultExternalAuthRepository: baseRepository}
	auth.identityStore = repository
	return auth, identities, repository
}

func TestUserSecurityProfileValidationAndLookupFailures(t *testing.T) {
	fault := errors.New("user security profile fault")

	t.Run("user required", func(t *testing.T) {
		auth, _, _ := newUserAdministrationFixture()
		_, err := auth.UserSecurityProfile(t.Context(), "workspace", " ")
		assertAuthErrorCode(t, err, "auth.user_required")
	})

	t.Run("identity lookup failure", func(t *testing.T) {
		auth, identities, _ := newUserAdministrationFixture()
		identities.listUsersErr = fault
		_, err := auth.UserSecurityProfile(t.Context(), "workspace", "user")
		assertAuthCause(t, err, fault)
	})

	t.Run("identity missing", func(t *testing.T) {
		auth, _, _ := newUserAdministrationFixture()
		_, err := auth.UserSecurityProfile(t.Context(), "workspace", "user")
		assertAuthErrorCode(t, err, "backend.identity.user_not_found")
	})

	t.Run("credential lookup failure", func(t *testing.T) {
		auth, identities, repository := newUserAdministrationFixture()
		identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
		repository.getCredentialErr = fault
		_, err := auth.UserSecurityProfile(t.Context(), "workspace", "user")
		assertAuthCause(t, err, fault)
	})

	t.Run("session lookup failure", func(t *testing.T) {
		auth, identities, repository := newUserAdministrationFixture()
		identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
		repository.listSessionsErr = fault
		profile, err := auth.UserSecurityProfile(t.Context(), "workspace", "user")
		assertAuthCause(t, err, fault)
		if profile.Sessions == nil || profile.ExternalAccounts == nil {
			t.Fatalf("partial profile collections must be initialized: %#v", profile)
		}
	})

	t.Run("external account lookup failure", func(t *testing.T) {
		auth, identities, repository := newUserAdministrationFixture()
		identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
		repository.listAccountsErr = fault
		_, err := auth.UserSecurityProfile(t.Context(), "workspace", "user")
		assertAuthCause(t, err, fault)
	})

	t.Run("MFA lookup failure", func(t *testing.T) {
		auth, identities, repository := newUserAdministrationFixture()
		identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
		repository.listMFAErr = fault
		profile, err := auth.UserSecurityProfile(t.Context(), "workspace", "user")
		assertAuthCause(t, err, fault)
		if profile.MFAFactors == nil {
			t.Fatal("partial MFA collection must be initialized")
		}
	})
}

func TestUserSecurityProfileProjectsCredentialSessionsAndAccounts(t *testing.T) {
	auth, identities, repository := newUserAdministrationFixture()
	identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
	repository.credentials = map[string]identitymodel.IdentityCredential{
		"user": {UserID: "user", PasswordHash: "credential-secret", FailedLoginCount: 3, LockedUntil: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
	}
	repository.refreshTokens = []identitymodel.AuthRefreshToken{
		{ID: "active", TokenHash: "refresh-secret", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
		{ID: "revoked", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), RevokedAt: time.Now().UTC().Format(time.RFC3339)},
		{ID: "expired", ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)},
		{ID: "legacy-invalid-expiry", ExpiresAt: "not-a-time"},
	}
	repository.accounts = []identitymodel.IdentityExternalAccount{{ID: "account", UserID: "user", Provider: "oidc", ProviderSubject: "provider-secret", Metadata: "metadata-secret"}}
	repository.mfaFactors = []identitymodel.IdentityMFAFactor{
		{ID: "active-factor", UserID: "user", Type: "totp", Status: "active", VerifiedAt: time.Now().UTC().Format(time.RFC3339)},
		{ID: "active-unverified-factor", UserID: "user", Type: "totp", Status: "active"},
		{ID: "pending-factor", UserID: "user", Type: "webauthn", Status: "pending"},
	}

	profile, err := auth.UserSecurityProfile(t.Context(), "workspace", " user ")
	if err != nil {
		t.Fatalf("profile error = %v", err)
	}
	if profile.Credential == nil || profile.Credential.UserID != "user" || !profile.Locked {
		t.Fatalf("credential projection = %#v", profile)
	}
	if profile.ActiveSessions != 2 {
		t.Fatalf("active sessions = %d, want 2", profile.ActiveSessions)
	}
	if len(profile.Sessions) != 4 || len(profile.ExternalAccounts) != 1 || len(profile.MFAFactors) != 3 || !profile.MFAEnabled {
		t.Fatalf("profile collections = %#v", profile)
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal security profile: %v", err)
	}
	for _, secret := range []string{"credential-secret", "refresh-secret", "provider-secret", "metadata-secret", "password_hash", "token_hash", "provider_subject"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("security profile leaked %q: %s", secret, encoded)
		}
	}
}

func TestMFAFactorAdministration(t *testing.T) {
	fault := errors.New("MFA repository fault")

	t.Run("register validation", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			userID string
			factor identitymodel.IdentityMFAFactor
			code   string
		}{
			{"user required", " ", identitymodel.IdentityMFAFactor{}, "auth.user_required"},
			{"factor id required", "user", identitymodel.IdentityMFAFactor{Type: "totp", VerifiedAt: "now"}, "auth.mfa_factor_id_required"},
			{"factor type invalid", "user", identitymodel.IdentityMFAFactor{ID: "factor", Type: "sms", VerifiedAt: "now"}, "auth.mfa_factor_type_invalid"},
			{"factor verification required", "user", identitymodel.IdentityMFAFactor{ID: "factor", Type: "totp"}, "auth.mfa_factor_not_verified"},
		} {
			t.Run(test.name, func(t *testing.T) {
				auth, _, _ := newUserAdministrationFixture()
				assertAuthErrorCode(t, auth.RegisterVerifiedMFAFactor(t.Context(), "workspace", test.userID, test.factor), test.code)
			})
		}
	})

	t.Run("register identity boundaries", func(t *testing.T) {
		auth, identities, _ := newUserAdministrationFixture()
		factor := identitymodel.IdentityMFAFactor{ID: "factor", Type: "webauthn", VerifiedAt: "now"}
		identities.listUsersErr = fault
		assertAuthCause(t, auth.RegisterVerifiedMFAFactor(t.Context(), "workspace", "user", factor), fault)
		identities.listUsersErr = nil
		assertAuthErrorCode(t, auth.RegisterVerifiedMFAFactor(t.Context(), "workspace", "user", factor), "backend.identity.user_not_found")
		identities.users = []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusDisabled}}
		assertAuthErrorCode(t, auth.RegisterVerifiedMFAFactor(t.Context(), "workspace", "user", factor), "auth.user_inactive")
	})

	t.Run("register success and persistence failure", func(t *testing.T) {
		auth, identities, repository := newUserAdministrationFixture()
		identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
		factor := identitymodel.IdentityMFAFactor{ID: "factor", Type: "external", Status: "pending", VerifiedAt: "now"}
		repository.upsertMFAErr = fault
		assertAuthCause(t, auth.RegisterVerifiedMFAFactor(t.Context(), "workspace", "user", factor), fault)
		repository.upsertMFAErr = nil
		if err := auth.RegisterVerifiedMFAFactor(t.Context(), "workspace", " user ", factor); err != nil {
			t.Fatal(err)
		}
		stored := repository.mfaFactors[0]
		if stored.UserID != "user" || stored.Status != "active" {
			t.Fatalf("stored factor=%#v", stored)
		}
	})

	t.Run("optional persistence unavailable", func(t *testing.T) {
		auth, identities, repository := newUserAdministrationFixture()
		identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
		auth.identityStore = authRepositoryWithoutMFA{AuthRepository: repository}
		profile, err := auth.UserSecurityProfile(t.Context(), "workspace", "user")
		if err != nil || profile.MFAFactors == nil || profile.MFAEnabled {
			t.Fatalf("profile=%#v err=%v", profile, err)
		}
		factor := identitymodel.IdentityMFAFactor{ID: "factor", Type: "totp", VerifiedAt: "now"}
		assertAuthErrorCode(t, auth.RegisterVerifiedMFAFactor(t.Context(), "workspace", "user", factor), "auth.mfa_unavailable")
		assertAuthErrorCode(t, auth.RevokeMFAFactor(t.Context(), "workspace", "user", "factor"), "auth.mfa_unavailable")
	})

	t.Run("revoke boundaries and success", func(t *testing.T) {
		auth, identities, repository := newUserAdministrationFixture()
		assertAuthErrorCode(t, auth.RevokeMFAFactor(t.Context(), "workspace", " ", "factor"), "auth.user_required")
		assertAuthErrorCode(t, auth.RevokeMFAFactor(t.Context(), "workspace", "user", " "), "auth.mfa_factor_id_required")
		identities.listUsersErr = fault
		assertAuthCause(t, auth.RevokeMFAFactor(t.Context(), "workspace", "user", "factor"), fault)
		identities.listUsersErr = nil
		assertAuthErrorCode(t, auth.RevokeMFAFactor(t.Context(), "workspace", "user", "factor"), "backend.identity.user_not_found")
		identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
		repository.revokeMFAErr = fault
		assertAuthCause(t, auth.RevokeMFAFactor(t.Context(), "workspace", "user", "factor"), fault)
		repository.revokeMFAErr = nil
		if err := auth.RevokeMFAFactor(t.Context(), "workspace", " user ", " factor "); err != nil {
			t.Fatal(err)
		}
		if repository.revokedUserID != "user" || repository.revokedFactorID != "factor" {
			t.Fatalf("revoke request=%#v", repository)
		}
	})
}

func TestUnlockUser(t *testing.T) {
	fault := errors.New("unlock fault")

	t.Run("user required", func(t *testing.T) {
		auth, _, _ := newUserAdministrationFixture()
		assertAuthErrorCode(t, auth.UnlockUser(t.Context(), "workspace", " "), "auth.user_required")
	})

	t.Run("credential lookup failure", func(t *testing.T) {
		auth, _, repository := newUserAdministrationFixture()
		repository.getCredentialErr = fault
		assertAuthCause(t, auth.UnlockUser(t.Context(), "workspace", "user"), fault)
	})

	t.Run("credential missing", func(t *testing.T) {
		auth, _, _ := newUserAdministrationFixture()
		assertAuthErrorCode(t, auth.UnlockUser(t.Context(), "workspace", "user"), "auth.credential_missing")
	})

	t.Run("credential update failure", func(t *testing.T) {
		auth, _, repository := newUserAdministrationFixture()
		repository.credentials = map[string]identitymodel.IdentityCredential{"user": {UserID: "user"}}
		repository.upsertCredentialErr = fault
		assertAuthCause(t, auth.UnlockUser(t.Context(), "workspace", "user"), fault)
	})

	t.Run("success", func(t *testing.T) {
		auth, _, repository := newUserAdministrationFixture()
		repository.credentials = map[string]identitymodel.IdentityCredential{
			"user": {UserID: "user", FailedLoginCount: 5, LockedUntil: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
		}
		if err := auth.UnlockUser(t.Context(), "workspace", " user "); err != nil {
			t.Fatalf("unlock error = %v", err)
		}
		credential := repository.credentials["user"]
		if credential.FailedLoginCount != 0 || credential.LockedUntil != "" {
			t.Fatalf("credential remains locked: %#v", credential)
		}
	})
}

func TestForceLogoutUser(t *testing.T) {
	fault := errors.New("force logout fault")

	t.Run("user required", func(t *testing.T) {
		auth, _, _ := newUserAdministrationFixture()
		count, err := auth.ForceLogoutUser(t.Context(), "workspace", " ")
		if count != 0 {
			t.Fatalf("revoked count = %d", count)
		}
		assertAuthErrorCode(t, err, "auth.user_required")
	})

	t.Run("identity lookup failure", func(t *testing.T) {
		auth, identities, _ := newUserAdministrationFixture()
		identities.listUsersErr = fault
		_, err := auth.ForceLogoutUser(t.Context(), "workspace", "user")
		assertAuthCause(t, err, fault)
	})

	t.Run("identity missing", func(t *testing.T) {
		auth, _, _ := newUserAdministrationFixture()
		_, err := auth.ForceLogoutUser(t.Context(), "workspace", "user")
		assertAuthErrorCode(t, err, "backend.identity.user_not_found")
	})

	t.Run("revoke failure", func(t *testing.T) {
		auth, identities, repository := newUserAdministrationFixture()
		identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
		repository.revokeUserErr = fault
		_, err := auth.ForceLogoutUser(t.Context(), "workspace", "user")
		assertAuthCause(t, err, fault)
	})

	t.Run("success", func(t *testing.T) {
		auth, identities, repository := newUserAdministrationFixture()
		identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
		repository.refreshTokens = []identitymodel.AuthRefreshToken{{ID: "one"}, {ID: "two"}}
		count, err := auth.ForceLogoutUser(t.Context(), "workspace", " user ")
		if err != nil || count != 2 {
			t.Fatalf("force logout: count=%d err=%v", count, err)
		}
		if repository.revokedUserID != "user" || repository.revokedAt == "" {
			t.Fatalf("revoke request not recorded: %#v", repository)
		}
		if _, err := time.Parse(time.RFC3339, repository.revokedAt); err != nil {
			t.Fatalf("revoked_at = %q: %v", repository.revokedAt, err)
		}
	})
}

func assertAuthErrorCode(t *testing.T, err error, want string) {
	t.Helper()
	if got := apperror.CodeOf(err); got != want {
		t.Fatalf("error code = %q, want %q (error: %v)", got, want, err)
	}
}

func assertAuthCause(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want cause %v", err, want)
	}
}
