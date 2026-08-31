package service

import (
	"errors"
	"testing"
	"time"

	apperror "github.com/domainry/domainry-foundation/apperror"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func newLockoutAuthDomainService(maxFailures int, lockDuration time.Duration) (*AuthDomainService, *faultExternalIdentityRepository, *faultExternalAuthRepository) {
	_, identityRepository, authRepository := newFaultAuthDomainService()
	auth := NewAuthDomainService(identityRepository, authRepository, "test-secret", "Password@2026", 0, 0, maxFailures, lockDuration, 0, 0, authpolicy.AuthPasswordPolicy{})
	return auth, identityRepository, authRepository
}

func authErrorCode(t *testing.T, err error) string {
	t.Helper()
	var appErr *apperror.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected AppError, got: %v", err)
	}
	return appErr.Code
}

// Regression for platform finding #12: an account lockout must lift once
// locked_until expires. The expired lock must not survive as stale
// failed_login_count accounting either, because a counter frozen at the
// threshold re-armed the full lock window on a single further bad attempt,
// keeping the account locked indefinitely until an admin unlock.
func TestExpiredLockLiftsOnLogin(t *testing.T) {
	const password = "CurrentPass1!"

	t.Run("correct password after expiry logs in and resets the counter", func(t *testing.T) {
		auth, identityRepository, authRepository := newLockoutAuthDomainService(3, 15*time.Minute)
		user := activeExternalIdentityUser("user", "user@example.com")
		identityRepository.users = []identitymodel.IdentityUser{user}
		credential := passwordCredential(t, "user", password)
		credential.FailedLoginCount = 3
		credential.LockedUntil = time.Now().UTC().Add(-6 * time.Minute).Format(time.RFC3339)
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"user": credential}

		session, err := auth.Login(t.Context(), "workspace-primary", user.Email, password)
		if err != nil {
			t.Fatalf("expired lock with the correct password must allow login, got: %v", err)
		}
		if session.AccessToken == "" {
			t.Fatal("expected an issued session")
		}
		stored := authRepository.credentials["user"]
		if stored.FailedLoginCount != 0 || stored.LockedUntil != "" {
			t.Fatalf("expired lock must reset failure accounting, got failed=%d locked=%q", stored.FailedLoginCount, stored.LockedUntil)
		}
	})

	t.Run("single failure after expiry must not re-arm the full lock", func(t *testing.T) {
		auth, identityRepository, authRepository := newLockoutAuthDomainService(3, 15*time.Minute)
		user := activeExternalIdentityUser("user", "user@example.com")
		identityRepository.users = []identitymodel.IdentityUser{user}
		credential := passwordCredential(t, "user", password)
		credential.FailedLoginCount = 3
		credential.LockedUntil = time.Now().UTC().Add(-6 * time.Minute).Format(time.RFC3339)
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"user": credential}

		_, err := auth.Login(t.Context(), "workspace-primary", user.Email, "WrongPass1!")
		if code := authErrorCode(t, err); code != "auth.invalid_credentials" {
			t.Fatalf("bad password after lock expiry must report invalid credentials, got %q", code)
		}
		if _, err := auth.Login(t.Context(), "workspace-primary", user.Email, password); err != nil {
			t.Fatalf("one stale failure must not re-lock the account, got: %v", err)
		}
	})

	t.Run("active lock still denies the correct password", func(t *testing.T) {
		auth, identityRepository, authRepository := newLockoutAuthDomainService(3, 15*time.Minute)
		user := activeExternalIdentityUser("user", "user@example.com")
		identityRepository.users = []identitymodel.IdentityUser{user}
		credential := passwordCredential(t, "user", password)
		credential.FailedLoginCount = 3
		credential.LockedUntil = time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"user": credential}

		_, err := auth.Login(t.Context(), "workspace-primary", user.Email, password)
		if code := authErrorCode(t, err); code != "auth.account_locked" {
			t.Fatalf("active lock must stay enforced, got %q", code)
		}
	})

	t.Run("repeated failures still escalate to a fresh lock", func(t *testing.T) {
		auth, identityRepository, authRepository := newLockoutAuthDomainService(3, 15*time.Minute)
		user := activeExternalIdentityUser("user", "user@example.com")
		identityRepository.users = []identitymodel.IdentityUser{user}
		credential := passwordCredential(t, "user", password)
		credential.FailedLoginCount = 3
		credential.LockedUntil = time.Now().UTC().Add(-6 * time.Minute).Format(time.RFC3339)
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"user": credential}

		for i := 0; i < 3; i++ {
			if _, err := auth.Login(t.Context(), "workspace-primary", user.Email, "WrongPass1!"); err == nil {
				t.Fatal("bad password must fail")
			}
		}
		_, err := auth.Login(t.Context(), "workspace-primary", user.Email, password)
		if code := authErrorCode(t, err); code != "auth.account_locked" {
			t.Fatalf("three fresh failures must install a fresh lock, got %q", code)
		}
	})

	t.Run("change password lifts an expired lock the same way", func(t *testing.T) {
		auth, identityRepository, authRepository := newLockoutAuthDomainService(3, 15*time.Minute)
		user := activeExternalIdentityUser("user", "user@example.com")
		identityRepository.users = []identitymodel.IdentityUser{user}
		credential := passwordCredential(t, "user", password)
		credential.FailedLoginCount = 3
		credential.LockedUntil = time.Now().UTC().Add(-6 * time.Minute).Format(time.RFC3339)
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"user": credential}

		if err := auth.ChangePassword(t.Context(), "workspace-primary", user.ID, password, "NewPassword2!"); err != nil {
			t.Fatalf("expired lock with the correct password must allow a password change, got: %v", err)
		}
		stored := authRepository.credentials["user"]
		if stored.LockedUntil != "" {
			t.Fatalf("expired lock must be cleared by the password change, got locked=%q", stored.LockedUntil)
		}
	})
}
