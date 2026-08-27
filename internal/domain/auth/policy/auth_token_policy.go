package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func AuthSignClaims(claims authmodel.AuthClaims, secret []byte) string {
	return AuthSignClaimsWithKID(claims, secret, "")
}

func AuthSignClaimsWithKID(claims authmodel.AuthClaims, secret []byte, kid string) string {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	if strings.TrimSpace(kid) != "" {
		header["kid"] = strings.TrimSpace(kid)
	}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	return signed + "." + AuthSignHS256([]byte(signed), secret)
}

func AuthSignHS256(value []byte, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(value)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func AuthHashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func AuthTokenExpired(value string, now time.Time) bool {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	return err != nil || !parsed.After(now)
}

func AuthBearerToken(authorization string) string {
	parts := strings.Fields(strings.TrimSpace(authorization))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
