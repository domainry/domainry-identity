package authmodel

type AuthSession struct {
	SessionID             string     `json:"session_id"`
	TenantID              string     `json:"tenant_id"`
	WorkspaceID           string     `json:"workspace_id"`
	AccessToken           string     `json:"access_token"`
	RefreshToken          string     `json:"refresh_token,omitempty"`
	TokenType             string     `json:"token_type"`
	ExpiresAt             string     `json:"expires_at"`
	User                  AuthUser   `json:"user"`
	Roles                 []AuthRole `json:"roles"`
	DefaultRole           string     `json:"default_role"`
	Permissions           []string   `json:"permissions"`
	MustChangePassword    bool       `json:"must_change_password"`
	AuthenticationTime    int64      `json:"auth_time,omitempty"`
	AuthenticationMethods []string   `json:"amr,omitempty"`
	AssuranceLevel        string     `json:"acr,omitempty"`
}

type AuthenticationContext struct {
	AuthenticationTime int64
	Methods            []string
	AssuranceLevel     string
}

type AuthenticationOutcome struct {
	Status    string                 `json:"status"`
	Session   *AuthSession           `json:"session,omitempty"`
	Challenge *AuthProviderChallenge `json:"challenge,omitempty"`
}

const (
	AuthenticationStatusAuthenticated     = "authenticated"
	AuthenticationStatusChallengeRequired = "challenge_required"
)
