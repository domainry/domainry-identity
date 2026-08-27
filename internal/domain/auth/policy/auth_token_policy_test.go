package policy

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestAuthSigningAndHashingPolicy(t *testing.T) {
	claims := authmodel.AuthClaims{Subject: "user-1", WorkspaceID: "workspace-1", SessionID: "session-1", RoleKeys: []string{"admin"}, IssuedAt: 1, ExpiresAt: 2, JTI: "jti-1"}
	secret := []byte("secret")
	withoutKID := AuthSignClaims(claims, secret)
	withKID := AuthSignClaimsWithKID(claims, secret, " key-1 ")
	for _, test := range []struct {
		token string
		kid   string
	}{{withoutKID, ""}, {withKID, "key-1"}} {
		parts := strings.Split(test.token, ".")
		if len(parts) != 3 || parts[2] != AuthSignHS256([]byte(parts[0]+"."+parts[1]), secret) {
			t.Fatalf("invalid signed token %q", test.token)
		}
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		var header map[string]string
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			t.Fatal(err)
		}
		if header["alg"] != "HS256" || header["typ"] != "JWT" || header["kid"] != test.kid {
			t.Fatalf("header = %#v", header)
		}
	}
	if AuthSignHS256([]byte("value"), secret) == AuthSignHS256([]byte("value"), []byte("different")) {
		t.Fatal("signature must depend on secret")
	}
	if AuthHashRefreshToken(" token ") != AuthHashRefreshToken("token") || AuthHashRefreshToken("token") == AuthHashRefreshToken("other") {
		t.Fatal("refresh token hashing normalization mismatch")
	}
}

func TestAuthTokenExpiryAndBearerPolicyMatrix(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		value string
		want  bool
	}{{"invalid", true}, {now.Add(-time.Second).Format(time.RFC3339), true}, {now.Format(time.RFC3339), true}, {now.Add(time.Second).Format(time.RFC3339), false}} {
		if got := AuthTokenExpired(test.value, now); got != test.want {
			t.Fatalf("expired %q = %v, want %v", test.value, got, test.want)
		}
	}
	for _, test := range []struct {
		header string
		want   string
	}{{"Bearer token", "token"}, {" bearer   token ", "token"}, {"", ""}, {"Bearer", ""}, {"Basic token", ""}, {"Bearer one two", ""}} {
		if got := AuthBearerToken(test.header); got != test.want {
			t.Fatalf("bearer %q = %q, want %q", test.header, got, test.want)
		}
	}
}
