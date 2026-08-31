package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
)

func (s *AuthDomainService) signClaims(claims authmodel.AuthClaims) string {
	now := time.Now().UTC()
	claims.Issuer = valueOrDefault(claims.Issuer, s.issuer)
	claims.Audience = valueOrDefault(claims.Audience, s.audience)
	claims.TenantID = valueOrDefault(claims.TenantID, claims.WorkspaceID)
	if claims.AuthorizationRevision == "" && claims.Subject != "" {
		revision := sha256.Sum256([]byte(claims.WorkspaceID + "\x00" + claims.Subject))
		claims.AuthorizationRevision = base64.RawURLEncoding.EncodeToString(revision[:])
	}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now.Unix()
	}
	if claims.AuthenticationTime == 0 {
		claims.AuthenticationTime = claims.IssuedAt
	}
	if claims.JTI == "" && claims.Subject != "" {
		claims.JTI = randomToken()
	}
	headerJSON, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": s.activeKID})
	payloadJSON, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.activePrivateKey, []byte(signed)))
}

func signHS256(value []byte, secret []byte) string {
	return authpolicy.AuthSignHS256(value, secret)
}

func hashRefreshToken(token string) string {
	return authpolicy.AuthHashRefreshToken(token)
}

func tokenExpired(value string) bool {
	return authpolicy.AuthTokenExpired(value, time.Now())
}

func bearerToken(authorization string) string {
	return authpolicy.AuthBearerToken(authorization)
}
