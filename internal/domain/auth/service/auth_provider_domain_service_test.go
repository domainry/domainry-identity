// Auth-provider domain service tests.
package service

import (
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	"testing"
)

func TestAuthProviderDomainServiceOwnsTypedConfig(t *testing.T) {
	application := NewAuthProviderDomainService([]map[string]any{{"key": "oidc", "label": "OIDC", "type": "oidc", "auth_url": "https://id.example/auth", "enabled": false, "auto_create_users": false, "role_mappings": []any{map[string]any{"claim": "group", "match": "admin", "role_key": "admin"}}}}, true)
	config, ok := application.Find(t.Context(), "OIDC")
	if !ok || config.Key != "oidc" || config.AuthURL == "" || len(config.RoleMappings) != 1 {
		t.Fatalf("typed config=%#v ok=%v", config, ok)
	}
	if policy := application.AuthExternalLoginPolicy(t.Context(), config); policy.AutoCreateUsers {
		t.Fatalf("explicit false auto-create was ignored: %#v", policy)
	}
	config.ClientID, config.ClientSecret, config.RedirectURL = "client", "secret", "https://app.example/callback"
	config.Enabled, config.ClientSecretConfigured = true, true
	updated, ok := application.ReplaceConfig(config)
	if !ok || !updated.Enabled || !updated.ClientSecretConfigured {
		t.Fatalf("updated=%#v ok=%v", updated, ok)
	}
	safe := updated.SafeMap()
	if _, exists := safe["client_secret"]; exists {
		t.Fatalf("safe config leaked secret: %#v", safe)
	}
	if enabled, ok := application.Enabled(t.Context(), "oidc"); !ok || enabled.ClientID != "client" {
		t.Fatalf("enabled=%#v ok=%v", enabled, ok)
	}
	if _, ok := application.ReplaceConfig(authmodel.AuthProviderConfig{Key: "unknown"}); ok {
		t.Fatal("unknown provider replacement must fail")
	}
}

func TestAuthProviderDiscoveryHidesActionOnlyOTP(t *testing.T) {
	providers := NewAuthProviderDomainService([]map[string]any{
		{"key": "action_pin", "type": "otp", "enabled": true, "allowed_purposes": []any{authmodel.AuthChallengePurposeAction}},
		{"key": "login_pin", "type": "otp", "enabled": true, "allowed_purposes": []any{authmodel.AuthChallengePurposeLogin}},
	}, false)
	values := providers.ListSafe(t.Context())
	if len(values) != 1 || values[0]["key"] != "login_pin" {
		t.Fatalf("login discovery=%#v", values)
	}
}
