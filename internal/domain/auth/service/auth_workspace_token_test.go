package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestWorkspaceTokenIssuanceRequiresWorkspace(t *testing.T) {
	auth, _, _ := newFaultAuthDomainService()
	token := mustSignClaims(t, auth, authmodel.AuthClaims{Subject: "user", WorkspaceID: "workspace-primary", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if _, found := claims["tenant_id"]; found {
		t.Fatal("new token still issues tenant_id")
	}
	if _, err := auth.VerifySignedAccessToken(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, workspace string
		allowed         bool
	}{
		{"valid workspace", "workspace-primary", true},
		{"missing workspace", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims["workspace_id"] = tc.workspace
			payload, _ := json.Marshal(claims)
			signed := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
			token := signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(auth.activePrivateKey, []byte(signed)))
			_, err := auth.VerifySignedAccessToken(t.Context(), token)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v error=%v", tc.allowed, err)
			}
		})
	}
}
