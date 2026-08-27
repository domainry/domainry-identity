package projection

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

// AuthMeResponse is the authenticated identity projection returned to callers.
type AuthMeResponse struct {
	User               authmodel.AuthUser   `json:"user"`
	Roles              []authmodel.AuthRole `json:"roles"`
	DefaultRole        string               `json:"default_role"`
	Permissions        []string             `json:"permissions"`
	MustChangePassword bool                 `json:"must_change_password"`
}

// AuthProviderStartResponse is the public projection for an external login challenge.
type AuthProviderStartResponse struct {
	Provider  string `json:"provider"`
	State     string `json:"state"`
	Nonce     string `json:"nonce,omitempty"`
	Code      string `json:"code,omitempty"`
	AuthURL   string `json:"auth_url,omitempty"`
	ExpiresAt string `json:"expires_at"`
}
