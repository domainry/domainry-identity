package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

func (s *AuthDomainService) VerifyAccessToken(ctx context.Context, token string) (authmodel.AuthClaims, error) {
	claims, err := s.VerifySignedAccessToken(ctx, token)
	if err != nil {
		return authmodel.AuthClaims{}, err
	}
	if claims.ServiceApplicationKey != "" {
		return authmodel.AuthClaims{}, forbidden("auth.user_token_required")
	}
	now := time.Now()
	sessions, ok := s.identityStore.(authrepository.AuthSessionRepository)
	if !ok {
		return claims, forbidden("auth.session_expired")
	}
	state, err := sessions.AuthSessionState(ctx, claims.WorkspaceID, claims.Subject, claims.SessionID, now)
	if err != nil {
		return claims, err
	}
	switch state {
	case authrepository.AuthSessionStateActive:
	case authrepository.AuthSessionStateRevoked:
		return claims, forbidden("auth.session_revoked")
	default:
		return claims, forbidden("auth.session_expired")
	}
	return claims, nil
}

// VerifySignedAccessToken performs the public-key resource-server check only.
// It deliberately does not query session persistence: Runtime caches the
// subsequently resolved session and AccessBundle for a bounded interval, while
// high-risk reauthorization still reaches the authoritative Identity service.
func (s *AuthDomainService) VerifySignedAccessToken(ctx context.Context, token string) (authmodel.AuthClaims, error) {
	var claims authmodel.AuthClaims
	if err := ctx.Err(); err != nil {
		return claims, err
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return claims, forbidden("auth.invalid_token")
	}
	headerPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, forbidden("auth.invalid_token")
	}
	var header map[string]string
	if json.Unmarshal(headerPayload, &header) != nil || header["alg"] != "EdDSA" || header["typ"] != "JWT" {
		return claims, forbidden("auth.invalid_token")
	}
	kid := strings.TrimSpace(header["kid"])
	selected, ok := s.verificationKeys[kid]
	if !ok {
		return claims, forbidden("auth.invalid_token")
	}
	signed := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(selected, []byte(signed), signature) {
		return claims, forbidden("auth.invalid_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, forbidden("auth.invalid_token")
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, forbidden("auth.invalid_token")
	}
	now := time.Now()
	claims.WorkspaceID = valueOrDefault(claims.WorkspaceID, "default")
	// Audience is application-scoped. Registration is checked before issuance
	// and resource servers compare it with their expected ApplicationKey. The
	// Identity issuer therefore validates presence here instead of incorrectly
	// forcing every application token to the process-wide default audience.
	if claims.Issuer != s.issuer || strings.TrimSpace(claims.Audience) == "" || claims.Subject == "" || claims.TenantID == "" || claims.SessionID == "" || claims.AuthorizationRevision == "" || claims.JTI == "" || claims.IssuedAt > now.Add(time.Minute).Unix() || claims.ExpiresAt <= now.Unix() {
		return claims, forbidden("auth.session_expired")
	}
	return claims, nil
}
