package service

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestRefreshSessionValidation(t *testing.T) {
	auth, _, _ := newFaultAuthDomainService()
	if _, err := auth.Refresh(t.Context(), "workspace-primary", " "); err == nil {
		t.Fatal("expected blank refresh token to fail")
	}

	fault := errors.New("refresh lookup fault")
	t.Run("repository lookup failure", func(t *testing.T) {
		auth, _, authRepository := newFaultAuthDomainService()
		authRepository.getRefreshTokenErr = fault
		_, err := auth.Refresh(t.Context(), "workspace-primary", "refresh-token")
		assertExternalAuthFault(t, err, fault)
	})

	for _, testCase := range []struct {
		name      string
		configure func(*faultExternalAuthRepository)
	}{
		{name: "unknown token"},
		{name: "revoked token", configure: func(repository *faultExternalAuthRepository) {
			repository.refreshTokens = []identitymodel.AuthRefreshToken{validRefreshRecord("refresh-token", "user")}
			repository.refreshTokens[0].RevokedAt = time.Now().UTC().Format(time.RFC3339)
		}},
		{name: "expired token", configure: func(repository *faultExternalAuthRepository) {
			repository.refreshTokens = []identitymodel.AuthRefreshToken{validRefreshRecord("refresh-token", "user")}
			repository.refreshTokens[0].ExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339)
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			auth, _, authRepository := newFaultAuthDomainService()
			if testCase.configure != nil {
				testCase.configure(authRepository)
			}
			if _, err := auth.Refresh(t.Context(), "workspace-primary", "refresh-token"); err == nil {
				t.Fatal("expected invalid refresh session")
			}
		})
	}
}

func TestRefreshSessionIdentityValidation(t *testing.T) {
	fault := errors.New("refresh identity fault")

	t.Run("identity lookup failure", func(t *testing.T) {
		auth, identityRepository, _ := validRefreshFixture()
		identityRepository.listUsersErr = fault
		_, err := auth.Refresh(t.Context(), "workspace-primary", "refresh-token")
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("identity missing", func(t *testing.T) {
		auth, identityRepository, _ := validRefreshFixture()
		identityRepository.users = nil
		if _, err := auth.Refresh(t.Context(), "workspace-primary", "refresh-token"); err == nil {
			t.Fatal("expected missing refresh identity to fail")
		}
	})

	t.Run("identity disabled", func(t *testing.T) {
		auth, identityRepository, _ := validRefreshFixture()
		identityRepository.users[0].Status = identitymodel.IdentityStatusDisabled
		if _, err := auth.Refresh(t.Context(), "workspace-primary", "refresh-token"); err == nil {
			t.Fatal("expected disabled refresh identity to fail")
		}
	})

	t.Run("session issuance failure", func(t *testing.T) {
		auth, identityRepository, _ := validRefreshFixture()
		identityRepository.listAssignmentsErr = fault
		_, err := auth.Refresh(t.Context(), "workspace-primary", "refresh-token")
		assertExternalAuthFault(t, err, fault)
	})
}

func TestRefreshSessionRotation(t *testing.T) {
	fault := errors.New("refresh rotation fault")

	t.Run("revocation failure", func(t *testing.T) {
		auth, _, authRepository := validRefreshFixture()
		authRepository.revokeRefreshTokenErr = fault
		_, err := auth.Refresh(t.Context(), "workspace-primary", "refresh-token")
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("successful rotation", func(t *testing.T) {
		auth, _, authRepository := validRefreshFixture()
		result, err := auth.Refresh(t.Context(), "workspace-primary", "refresh-token")
		if err != nil {
			t.Fatalf("rotate refresh token: %v", err)
		}
		if result.RefreshToken == "refresh-token" || len(authRepository.refreshTokens) != 2 || len(authRepository.revokedRefreshTokens) != 1 {
			t.Fatalf("unexpected refresh rotation: result=%#v repository=%#v", result, authRepository)
		}
		claims, err := auth.VerifyAccessToken(t.Context(), result.AccessToken)
		if err != nil || claims.SessionID != "session" {
			t.Fatalf("refresh changed logical session: claims=%#v err=%v", claims, err)
		}
	})

	t.Run("application mismatch is rejected before rotation", func(t *testing.T) {
		auth, _, authRepository := validRefreshFixture()
		authRepository.refreshTokens[0].Audience = "orders-runtime"
		if _, err := auth.RefreshForApplication(t.Context(), "workspace-primary", "refresh-token", "billing-runtime"); err == nil {
			t.Fatal("refresh credential was accepted by another application")
		}
		if len(authRepository.refreshTokens) != 1 || len(authRepository.revokedRefreshTokens) != 0 || authRepository.refreshTokens[0].RevokedAt != "" {
			t.Fatalf("rejected refresh credential was mutated: %#v", authRepository.refreshTokens)
		}
		result, err := auth.RefreshForApplication(t.Context(), "workspace-primary", "refresh-token", "orders-runtime")
		if err != nil {
			t.Fatal(err)
		}
		claims, err := auth.VerifyAccessToken(t.Context(), result.AccessToken)
		if err != nil || claims.Audience != "orders-runtime" {
			t.Fatalf("rotated audience=%q err=%v", claims.Audience, err)
		}
	})

	t.Run("concurrent token consumption succeeds once", func(t *testing.T) {
		auth, _, _ := validRefreshFixture()
		var success atomic.Int32
		var wait sync.WaitGroup
		start := make(chan struct{})
		for range 32 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				if _, err := auth.Refresh(t.Context(), "workspace-primary", "refresh-token"); err == nil {
					success.Add(1)
				}
			}()
		}
		close(start)
		wait.Wait()
		if success.Load() != 1 {
			t.Fatalf("successful concurrent rotations=%d want 1", success.Load())
		}
	})
}

func TestLogoutSession(t *testing.T) {
	auth, _, authRepository := validRefreshFixture()
	auth.Logout(t.Context(), "workspace-primary", " ")

	authRepository.getRefreshTokenErr = errors.New("ignored lookup failure")
	auth.Logout(t.Context(), "workspace-primary", "refresh-token")
	authRepository.getRefreshTokenErr = nil
	auth.Logout(t.Context(), "workspace-primary", "unknown")
	authRepository.revokeRefreshTokenErr = errors.New("ignored revoke failure")
	auth.Logout(t.Context(), "workspace-primary", "refresh-token")
	authRepository.revokeRefreshTokenErr = nil
	auth.Logout(t.Context(), "workspace-primary", "refresh-token")
	if len(authRepository.revokedRefreshTokens) != 1 || authRepository.revokedRefreshTokens[0] != "refresh-old" {
		t.Fatalf("unexpected logout revocations: %#v", authRepository.revokedRefreshTokens)
	}
}

func TestLogoutSessionRejectsAnotherApplicationBeforeRevocation(t *testing.T) {
	auth, _, authRepository := validRefreshFixture()
	authRepository.refreshTokens[0].Audience = "orders-runtime"
	if err := auth.LogoutForApplication(t.Context(), "workspace-primary", "refresh-token", "billing-runtime"); err == nil {
		t.Fatal("logout credential was accepted by another application")
	}
	if len(authRepository.revokedRefreshTokens) != 0 || authRepository.refreshTokens[0].RevokedAt != "" {
		t.Fatalf("rejected logout mutated the session: %#v", authRepository.refreshTokens)
	}
}

func validRefreshFixture() (*AuthDomainService, *faultExternalIdentityRepository, *faultExternalAuthRepository) {
	auth, identityRepository, authRepository := newFaultAuthDomainService()
	identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
	authRepository.refreshTokens = []identitymodel.AuthRefreshToken{validRefreshRecord("refresh-token", "user")}
	return auth, identityRepository, authRepository
}

func validRefreshRecord(rawToken string, userID string) identitymodel.AuthRefreshToken {
	return identitymodel.AuthRefreshToken{
		ID:        "refresh-old",
		UserID:    userID,
		SessionID: "session",
		TokenHash: hashRefreshToken(rawToken),
		ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339),
	}
}
