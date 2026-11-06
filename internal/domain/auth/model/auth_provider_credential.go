package authmodel

// AuthProviderCredential is Identity-owned configuration for an external
// login provider. It deliberately lives in Auth instead of a generic
// Integration domain: OIDC/SSO credentials are part of the login boundary.
type AuthProviderCredential struct {
	ProviderKey            string                    `json:"provider_key"`
	Label                  string                    `json:"label,omitempty"`
	ConnectionKey          string                    `json:"connection_key,omitempty"`
	WorkspaceID            string                    `json:"workspace_id,omitempty"`
	Type                   string                    `json:"type,omitempty"`
	Adapter                string                    `json:"adapter,omitempty"`
	Issuer                 string                    `json:"issuer,omitempty"`
	AuthURL                string                    `json:"auth_url,omitempty"`
	TokenURL               string                    `json:"token_url,omitempty"`
	UserInfoURL            string                    `json:"userinfo_url,omitempty"`
	Scope                  string                    `json:"scope,omitempty"`
	ListUsersURL           string                    `json:"list_users_url,omitempty"`
	ClientID               string                    `json:"client_id,omitempty"`
	ClientSecret           string                    `json:"-"`
	VerificationKey        string                    `json:"-"`
	RedirectURL            string                    `json:"redirect_url,omitempty"`
	LDAPURL                string                    `json:"ldap_url,omitempty"`
	LDAPStartTLS           bool                      `json:"ldap_start_tls,omitempty"`
	LDAPBindDN             string                    `json:"ldap_bind_dn,omitempty"`
	LDAPUsersDN            string                    `json:"ldap_users_dn,omitempty"`
	LDAPUserSearchFilter   string                    `json:"ldap_user_search_filter,omitempty"`
	LDAPUsernameAttribute  string                    `json:"ldap_username_attribute,omitempty"`
	LDAPUUIDAttribute      string                    `json:"ldap_uuid_attribute,omitempty"`
	LDAPEmailAttribute     string                    `json:"ldap_email_attribute,omitempty"`
	LDAPFirstNameAttribute string                    `json:"ldap_first_name_attribute,omitempty"`
	LDAPLastNameAttribute  string                    `json:"ldap_last_name_attribute,omitempty"`
	OTPProvider            string                    `json:"otp_provider,omitempty"`
	AllowedPurposes        []string                  `json:"allowed_purposes,omitempty"`
	AutoCreateUsers        bool                      `json:"auto_create_users"`
	DefaultRoleKey         string                    `json:"default_role_key,omitempty"`
	RoleMappings           []AuthProviderRoleMapping `json:"role_mappings,omitempty"`
	UpdatedBy              string                    `json:"updated_by,omitempty"`
	CreatedAt              string                    `json:"created_at,omitempty"`
	UpdatedAt              string                    `json:"updated_at,omitempty"`
}

type AuthProviderRoleMapping struct {
	Claim   string `json:"claim"`
	Match   string `json:"match"`
	RoleKey string `json:"role_key"`
}

type AuthProviderCredentialUpsertRequest struct {
	Label                  string                    `json:"label,omitempty"`
	ConnectionKey          string                    `json:"connection_key,omitempty"`
	Type                   string                    `json:"type,omitempty"`
	Adapter                string                    `json:"adapter,omitempty"`
	Issuer                 string                    `json:"issuer,omitempty"`
	AuthURL                string                    `json:"auth_url,omitempty"`
	TokenURL               string                    `json:"token_url,omitempty"`
	UserInfoURL            string                    `json:"userinfo_url,omitempty"`
	Scope                  string                    `json:"scope,omitempty"`
	ListUsersURL           string                    `json:"list_users_url,omitempty"`
	ClientID               string                    `json:"client_id,omitempty"`
	ClientSecret           string                    `json:"client_secret,omitempty"`
	VerificationKey        string                    `json:"verification_key,omitempty"`
	RedirectURL            string                    `json:"redirect_url,omitempty"`
	LDAPURL                string                    `json:"ldap_url,omitempty"`
	LDAPStartTLS           bool                      `json:"ldap_start_tls,omitempty"`
	LDAPBindDN             string                    `json:"ldap_bind_dn,omitempty"`
	LDAPBindPassword       string                    `json:"ldap_bind_password,omitempty"`
	LDAPUsersDN            string                    `json:"ldap_users_dn,omitempty"`
	LDAPUserSearchFilter   string                    `json:"ldap_user_search_filter,omitempty"`
	LDAPUsernameAttribute  string                    `json:"ldap_username_attribute,omitempty"`
	LDAPUUIDAttribute      string                    `json:"ldap_uuid_attribute,omitempty"`
	LDAPEmailAttribute     string                    `json:"ldap_email_attribute,omitempty"`
	LDAPFirstNameAttribute string                    `json:"ldap_first_name_attribute,omitempty"`
	LDAPLastNameAttribute  string                    `json:"ldap_last_name_attribute,omitempty"`
	LDAPCACertificate      string                    `json:"ldap_ca_certificate,omitempty"`
	OTPProvider            string                    `json:"otp_provider,omitempty"`
	AllowedPurposes        []string                  `json:"allowed_purposes,omitempty"`
	AutoCreateUsers        *bool                     `json:"auto_create_users,omitempty"`
	DefaultRoleKey         string                    `json:"default_role_key,omitempty"`
	RoleMappings           []AuthProviderRoleMapping `json:"role_mappings,omitempty"`
}
