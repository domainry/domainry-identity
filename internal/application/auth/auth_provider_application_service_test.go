package auth

import (
	"testing"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestMergeTypedAuthProviderCredentials(t *testing.T) {
	merged := MergeTypedAuthProviderCredentials([]map[string]any{{"key": "oidc", "type": "oidc"}}, []authmodel.AuthProviderCredential{{ProviderKey: "oidc", ClientID: "client", ClientSecret: "secret", RedirectURL: "url"}})
	if len(merged) != 1 || merged[0]["client_id"] != "client" {
		t.Fatalf("merged=%#v", merged)
	}
}
