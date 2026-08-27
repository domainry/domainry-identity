package authmodel

type AuthSession struct {
	SessionID          string     `json:"session_id"`
	TenantID           string     `json:"tenant_id"`
	WorkspaceID        string     `json:"workspace_id"`
	AccessToken        string     `json:"access_token"`
	RefreshToken       string     `json:"refresh_token,omitempty"`
	TokenType          string     `json:"token_type"`
	ExpiresAt          string     `json:"expires_at"`
	User               AuthUser   `json:"user"`
	Roles              []AuthRole `json:"roles"`
	DefaultRole        string     `json:"default_role"`
	Permissions        []string   `json:"permissions"`
	MustChangePassword bool       `json:"must_change_password"`
}
