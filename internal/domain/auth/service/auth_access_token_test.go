package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestAccessTokenVerification(t *testing.T) {
	auth, _, repository := newFaultAuthDomainService()

	if _, err := auth.VerifyAccessToken(t.Context(), "not-a-token"); err == nil {
		t.Fatal("expected malformed token to fail")
	}
	repository.refreshTokens = []identitymodel.AuthRefreshToken{{UserID: "user", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}}
	valid := mustSignClaims(t, auth, authmodel.AuthClaims{Subject: "user", WorkspaceID: "workspace-primary", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if _, err := auth.VerifyAccessToken(t.Context(), valid+"tampered"); err == nil {
		t.Fatal("expected invalid signature to fail")
	}
	if _, err := auth.VerifyAccessToken(t.Context(), signedTestToken(auth, "%")); err == nil {
		t.Fatal("expected invalid payload encoding to fail")
	}
	if _, err := auth.VerifyAccessToken(t.Context(), signedTestToken(auth, base64.RawURLEncoding.EncodeToString([]byte("not-json")))); err == nil {
		t.Fatal("expected invalid claims JSON to fail")
	}
	if _, err := auth.VerifyAccessToken(t.Context(), mustSignClaims(t, auth, authmodel.AuthClaims{ExpiresAt: time.Now().Add(time.Hour).Unix()})); err == nil {
		t.Fatal("expected missing subject to fail")
	}
	if _, err := auth.VerifyAccessToken(t.Context(), mustSignClaims(t, auth, authmodel.AuthClaims{Subject: "user", ExpiresAt: time.Now().Add(-time.Minute).Unix()})); err == nil {
		t.Fatal("expected expired token to fail")
	}
	claims, err := auth.VerifyAccessToken(t.Context(), valid)
	if err != nil || claims.Subject != "user" {
		t.Fatalf("verify valid token: claims=%#v err=%v", claims, err)
	}
	applicationToken := mustSignClaims(t, auth, authmodel.AuthClaims{Audience: "orders-runtime", Subject: "user", WorkspaceID: "workspace-primary", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	applicationClaims, err := auth.VerifyAccessToken(t.Context(), applicationToken)
	if err != nil || applicationClaims.Audience != "orders-runtime" {
		t.Fatalf("verify application-scoped token: claims=%#v err=%v", applicationClaims, err)
	}
}

func TestAccessTokenVerificationFailsClosedForDurableSessionState(t *testing.T) {
	auth, _, repository := newFaultAuthDomainService()
	now := time.Now()
	claims := authmodel.AuthClaims{Subject: "user", WorkspaceID: "workspace-primary", SessionID: "session", ExpiresAt: now.Add(time.Hour).Unix()}
	token := mustSignClaims(t, auth, claims)
	if _, err := auth.VerifyAccessToken(t.Context(), token); apperror.CodeOf(err) != "auth.session_expired" {
		t.Fatalf("missing durable session error=%v", err)
	}
	repository.refreshTokens = []identitymodel.AuthRefreshToken{{UserID: "user", SessionID: "session", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), RevokedAt: now.Format(time.RFC3339)}}
	if signed, err := auth.VerifySignedAccessToken(t.Context(), token); err != nil || signed.Subject != "user" {
		t.Fatalf("bounded resource-server verification unexpectedly read session state: claims=%#v err=%v", signed, err)
	}
	if _, err := auth.VerifyAccessToken(t.Context(), token); apperror.CodeOf(err) != "auth.session_revoked" {
		t.Fatalf("revoked durable session error=%v", err)
	}
	repository.refreshTokens[0].RevokedAt = ""
	repository.refreshTokens[0].ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339)
	if _, err := auth.VerifyAccessToken(t.Context(), token); apperror.CodeOf(err) != "auth.session_expired" {
		t.Fatalf("expired durable session error=%v", err)
	}
	repository.authSessionStateErr = errors.New("session store unavailable")
	if _, err := auth.VerifyAccessToken(t.Context(), token); apperror.KindOf(err) != apperror.KindUnavailable ||
		apperror.CodeOf(err) != "auth.service_unavailable" || !errors.Is(err, repository.authSessionStateErr) {
		t.Fatalf("unavailable durable session error=%v", err)
	}
}

func TestAccessTokenVerificationBoundsStalledSessionLookup(t *testing.T) {
	for _, test := range []struct {
		name   string
		budget time.Duration
	}{
		{name: "default lookup deadline", budget: authSessionLookupTimeout},
		{name: "shorter caller deadline", budget: 25 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth, _, repository := newFaultAuthDomainService()
			token := validIdentityAccessToken(t, auth, "user", "workspace-primary")
			auth.identityStore = stalledSessionRepository{repository}
			ctx := t.Context()
			if test.budget < authSessionLookupTimeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, test.budget)
				defer cancel()
			}
			start := time.Now()
			_, err := auth.VerifyAccessToken(ctx, token)
			if apperror.KindOf(err) != apperror.KindUnavailable ||
				apperror.CodeOf(err) != "auth.service_unavailable" || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("stalled authoritative lookup error=%v", err)
			}
			if elapsed := time.Since(start); elapsed > test.budget+time.Second {
				t.Fatalf("lookup exceeded deadline: elapsed=%v, budget=%v", elapsed, test.budget)
			}
			auth.identityStore = repository
			if _, err := auth.VerifyAccessToken(t.Context(), token); err != nil {
				t.Fatalf("original token failed after session store recovered: %v", err)
			}
		})
	}
}

type stalledSessionRepository struct{ *faultExternalAuthRepository }

func (r stalledSessionRepository) AuthSessionState(ctx context.Context, _, _, _ string, _ time.Time) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		return "", errors.New("missing authoritative lookup deadline")
	}
	<-ctx.Done()
	return "", ctx.Err()
}

func TestAuthAccessTokenSigningKeyRotationOverlap(t *testing.T) {
	auth, _, repository := newFaultAuthDomainService()
	repository.refreshTokens = []identitymodel.AuthRefreshToken{{UserID: "user", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}}
	if err := auth.ConfigureSigningKeys("old-kid", "old-secret", nil); err != nil {
		t.Fatal(err)
	}
	oldToken := mustSignClaims(t, auth, authmodel.AuthClaims{Subject: "user", WorkspaceID: "workspace-primary", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err := auth.ConfigureSigningKeys("new-kid", "new-secret", map[string]string{"old-kid": "old-secret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.VerifyAccessToken(t.Context(), oldToken); err != nil {
		t.Fatalf("old key was not accepted during overlap: %v", err)
	}
	newToken := mustSignClaims(t, auth, authmodel.AuthClaims{Subject: "user", WorkspaceID: "workspace-primary", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if !strings.Contains(decodeJWTHeader(t, newToken), `"kid":"new-kid"`) {
		t.Fatalf("new token missing active kid: %s", newToken)
	}
	if err := auth.ConfigureSigningKeys("new-kid", "new-secret", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.VerifyAccessToken(t.Context(), oldToken); err == nil {
		t.Fatal("retired signing key remained valid after overlap")
	}
}

func mustSignClaims(t *testing.T, auth *AuthDomainService, claims authmodel.AuthClaims) string {
	t.Helper()
	token, err := auth.signClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func decodeJWTHeader(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	return string(decoded)
}

func signedTestToken(auth *AuthDomainService, encodedPayload string) string {
	signed := "e30." + encodedPayload
	return signed + "." + signHS256([]byte(signed), auth.secret)
}
