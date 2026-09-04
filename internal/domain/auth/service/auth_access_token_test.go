package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"encoding/base64"
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
