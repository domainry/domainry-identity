package authmodel

// AuthProviderCredential is Identity-owned configuration for an external
// login provider. It deliberately lives in Auth instead of a generic
// Integration domain: OIDC/SSO credentials are part of the login boundary.
type AuthProviderCredential struct {
	ProviderKey     string                    `json:"provider_key"`
	ConnectionKey   string                    `json:"connection_key,omitempty"`
	WorkspaceID     string                    `json:"workspace_id,omitempty"`
	Type            string                    `json:"type,omitempty"`
	Issuer          string                    `json:"issuer,omitempty"`
	AuthURL         string                    `json:"auth_url,omitempty"`
	TokenURL        string                    `json:"token_url,omitempty"`
	UserInfoURL     string                    `json:"userinfo_url,omitempty"`
	Scope           string                    `json:"scope,omitempty"`
	ListUsersURL    string                    `json:"list_users_url,omitempty"`
	ClientID        string                    `json:"client_id,omitempty"`
	ClientSecret    string                    `json:"-"`
	RedirectURL     string                    `json:"redirect_url,omitempty"`
	OTPProvider     string                    `json:"otp_provider,omitempty"`
	AccessToken     string                    `json:"-"`
	PhoneNumberID   string                    `json:"phone_number_id,omitempty"`
	AutoCreateUsers bool                      `json:"auto_create_users"`
	DefaultRoleKey  string                    `json:"default_role_key,omitempty"`
	RoleMappings    []AuthProviderRoleMapping `json:"role_mappings,omitempty"`
	UpdatedBy       string                    `json:"updated_by,omitempty"`
	CreatedAt       string                    `json:"created_at,omitempty"`
	UpdatedAt       string                    `json:"updated_at,omitempty"`
}

type AuthProviderRoleMapping struct {
	Claim   string `json:"claim"`
	Match   string `json:"match"`
	RoleKey string `json:"role_key"`
}

type AuthProviderCredentialUpsertRequest struct {
	ConnectionKey   string                    `json:"connection_key,omitempty"`
	Type            string                    `json:"type,omitempty"`
	Issuer          string                    `json:"issuer,omitempty"`
	AuthURL         string                    `json:"auth_url,omitempty"`
	TokenURL        string                    `json:"token_url,omitempty"`
	UserInfoURL     string                    `json:"userinfo_url,omitempty"`
	Scope           string                    `json:"scope,omitempty"`
	ListUsersURL    string                    `json:"list_users_url,omitempty"`
	ClientID        string                    `json:"client_id,omitempty"`
	ClientSecret    string                    `json:"client_secret,omitempty"`
	RedirectURL     string                    `json:"redirect_url,omitempty"`
	OTPProvider     string                    `json:"otp_provider,omitempty"`
	AccessToken     string                    `json:"access_token,omitempty"`
	PhoneNumberID   string                    `json:"phone_number_id,omitempty"`
	AutoCreateUsers *bool                     `json:"auto_create_users,omitempty"`
	DefaultRoleKey  string                    `json:"default_role_key,omitempty"`
	RoleMappings    []AuthProviderRoleMapping `json:"role_mappings,omitempty"`
}
