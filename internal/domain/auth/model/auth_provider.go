package authmodel

import (
	"fmt"
	"strings"
)

// AuthProviderConfig is the stable, secret-bearing provider configuration
// consumed by Auth provider flows. SafeMap must be used for public projection.
type AuthProviderConfig struct {
	Key                       string
	Label                     string
	Type                      string
	Adapter                   string
	Enabled                   bool
	Issuer                    string
	AuthURL                   string
	TokenURL                  string
	UserInfoURL               string
	ClientID                  string
	ClientSecret              string
	VerificationKey           string
	RedirectURL               string
	Scope                     string
	OTPProvider               string
	ConnectionKey             string
	AllowedPurposes           []string
	AutoCreateUsers           bool
	AutoCreateConfigured      bool
	DefaultRoleKey            string
	RoleMappings              []AuthExternalRoleMapping
	ClientSecretConfigured    bool
	VerificationKeyConfigured bool
	ConfiguredFrom            string
	UpdatedAt                 string
	Extra                     map[string]any
}

type AuthProviderCallbackInput struct {
	Method string
	Values map[string]string
}

func AuthProviderConfigFromMap(raw map[string]any) AuthProviderConfig {
	get := func(key string) string {
		value, _ := raw[key].(string)
		return strings.TrimSpace(value)
	}
	getBool := func(key string) bool { value, _ := raw[key].(bool); return value }
	_, autoCreateConfigured := raw["auto_create_users"]
	config := AuthProviderConfig{Key: get("key"), Label: get("label"), Type: get("type"), Adapter: get("adapter"), Enabled: getBool("enabled"), Issuer: get("issuer"), AuthURL: get("auth_url"), TokenURL: get("token_url"), UserInfoURL: get("userinfo_url"), ClientID: get("client_id"), ClientSecret: get("client_secret"), VerificationKey: get("verification_key"), RedirectURL: get("redirect_url"), Scope: get("scope"), OTPProvider: get("otp_provider"), ConnectionKey: get("connection_key"), AllowedPurposes: authProviderStringSlice(raw["allowed_purposes"]), AutoCreateUsers: getBool("auto_create_users"), AutoCreateConfigured: autoCreateConfigured, DefaultRoleKey: get("default_role_key"), ClientSecretConfigured: getBool("client_secret_configured"), VerificationKeyConfigured: getBool("verification_key_configured"), ConfiguredFrom: get("configured_from"), UpdatedAt: get("updated_at"), Extra: map[string]any{}}
	config.RoleMappings = authProviderRoleMappingsFromAny(raw["role_mappings"])
	for key, value := range raw {
		// OTP delivery credentials belong to Integration. Ignore legacy Identity
		// configuration instead of carrying it forward through Extra/SafeMap.
		switch key {
		case "access_token", "phone_number_id", "access_token_configured", "phone_number_id_configured":
			continue
		}
		config.Extra[key] = value
	}
	return config
}

func authProviderRoleMappingsFromAny(value any) []AuthExternalRoleMapping {
	if typed, ok := value.([]AuthExternalRoleMapping); ok {
		return append([]AuthExternalRoleMapping(nil), typed...)
	}
	out := []AuthExternalRoleMapping{}
	if typed, ok := value.([]map[string]string); ok {
		for _, item := range typed {
			out = append(out, AuthExternalRoleMapping{Claim: item["claim"], Match: item["match"], RoleKey: item["role_key"]})
		}
		return out
	}
	if typed, ok := value.([]any); ok {
		for _, raw := range typed {
			if item, ok := raw.(map[string]any); ok {
				claim, _ := item["claim"].(string)
				match, _ := item["match"].(string)
				roleKey, _ := item["role_key"].(string)
				out = append(out, AuthExternalRoleMapping{Claim: strings.TrimSpace(claim), Match: strings.TrimSpace(match), RoleKey: strings.TrimSpace(roleKey)})
			}
		}
	}
	return out
}

func (c AuthProviderConfig) Clone() AuthProviderConfig {
	c.Extra = authProviderCloneMap(c.Extra)
	c.RoleMappings = append([]AuthExternalRoleMapping(nil), c.RoleMappings...)
	c.AllowedPurposes = append([]string(nil), c.AllowedPurposes...)
	return c
}

func (c AuthProviderConfig) Map() map[string]any {
	out := authProviderCloneMap(c.Extra)
	for key, value := range map[string]any{"key": c.Key, "label": c.Label, "type": c.Type, "adapter": c.Adapter, "enabled": c.Enabled, "issuer": c.Issuer, "auth_url": c.AuthURL, "token_url": c.TokenURL, "userinfo_url": c.UserInfoURL, "client_id": c.ClientID, "client_secret": c.ClientSecret, "verification_key": c.VerificationKey, "redirect_url": c.RedirectURL, "scope": c.Scope, "otp_provider": c.OTPProvider, "connection_key": c.ConnectionKey, "auto_create_users": c.AutoCreateUsers, "default_role_key": c.DefaultRoleKey, "role_mappings": c.RoleMappings, "client_secret_configured": c.ClientSecretConfigured, "verification_key_configured": c.VerificationKeyConfigured, "configured_from": c.ConfiguredFrom, "updated_at": c.UpdatedAt} {
		if text, ok := value.(string); !ok || text != "" {
			out[key] = value
		}
	}
	if c.AllowedPurposes != nil {
		out["allowed_purposes"] = append([]string(nil), c.AllowedPurposes...)
	}
	if !c.AutoCreateConfigured {
		delete(out, "auto_create_users")
	}
	return out
}

// SupportsChallengePurpose keeps OTP enrollment separate from when the factor
// is required. Missing configuration preserves the historical all-purpose
// behavior; an explicit list can make a provider action-only or login-only.
func (c AuthProviderConfig) SupportsChallengePurpose(purpose string) bool {
	if !strings.EqualFold(strings.TrimSpace(c.Type), "otp") {
		return false
	}
	if c.AllowedPurposes == nil {
		return true
	}
	purpose = strings.TrimSpace(purpose)
	for _, candidate := range c.AllowedPurposes {
		if strings.TrimSpace(candidate) == purpose {
			return true
		}
	}
	return false
}

func NormalizeAuthProviderAllowedPurposes(values []string) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("allowed_purposes must not be empty")
	}
	allowed := map[string]bool{
		AuthChallengePurposeLogin: true, AuthChallengePurposeLoginMFA: true, AuthChallengePurposeAction: true,
	}
	out, seen := make([]string, 0, len(values)), map[string]bool{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if !allowed[value] {
			return nil, fmt.Errorf("unsupported challenge purpose %q", raw)
		}
		if seen[value] {
			return nil, fmt.Errorf("duplicate challenge purpose %q", value)
		}
		seen[value] = true
		out = append(out, value)
	}
	return out, nil
}

func authProviderStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func (c AuthProviderConfig) SafeMap() map[string]any {
	out := c.Map()
	delete(out, "client_secret")
	delete(out, "verification_key")
	delete(out, "access_token")
	delete(out, "phone_number_id")
	delete(out, "access_token_configured")
	delete(out, "phone_number_id_configured")
	return out
}

func authProviderCloneMap(value map[string]any) map[string]any {
	out := make(map[string]any, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}
