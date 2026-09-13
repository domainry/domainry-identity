package authmodel

import identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

type AuthClaims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Subject  string `json:"sub"`

	WorkspaceID           string             `json:"workspace_id"`
	SessionID             string             `json:"sid"`
	AuthorizationRevision string             `json:"authz_revision"`
	AuthenticationTime    int64              `json:"auth_time,omitempty"`
	AuthenticationMethods []string           `json:"amr,omitempty"`
	AssuranceLevel        string             `json:"acr,omitempty"`
	IssuedAt              int64              `json:"iat"`
	ExpiresAt             int64              `json:"exp"`
	JTI                   string             `json:"jti"`
	ServiceApplicationKey string             `json:"service_application_key,omitempty"`
	ServiceCredentialID   string             `json:"service_credential_id,omitempty"`
	ServiceGrants         []AuthServiceGrant `json:"service_grants,omitempty"`
	TokenPurpose          string             `json:"token_purpose,omitempty"`
	// RoleKeys remains source-compatible for callers during the protocol
	// transition, but is deliberately never serialized into access tokens.
	RoleKeys []string `json:"-"`
}

type AuthServiceGrant struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type AuthUser struct {
	ID      string                       `json:"id"`
	Name    string                       `json:"name"`
	Email   string                       `json:"email"`
	Locale  string                       `json:"locale"`
	Version int64                        `json:"version"`
	Status  identitymodel.IdentityStatus `json:"status"`
}

type AuthRole struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Label string `json:"label"`
}

type AuthProviderChallenge struct {
	WorkspaceID           string   `json:"workspace_id"`
	ApplicationKey        string   `json:"application_key,omitempty"`
	Provider              string   `json:"provider"`
	Type                  string   `json:"type,omitempty"`
	Purpose               string   `json:"purpose,omitempty"`
	Status                string   `json:"status,omitempty"`
	UserID                string   `json:"user_id,omitempty"`
	RedirectURL           string   `json:"redirect_url,omitempty"`
	State                 string   `json:"state"`
	Nonce                 string   `json:"nonce,omitempty"`
	CodeVerifier          string   `json:"code_verifier,omitempty"`
	RequestID             string   `json:"request_id,omitempty"`
	ReturnURL             string   `json:"return_url,omitempty"`
	Phone                 string   `json:"phone,omitempty"`
	Code                  string   `json:"code,omitempty"`
	MaskedDestination     string   `json:"masked_destination,omitempty"`
	RetryAt               string   `json:"retry_at,omitempty"`
	DeliveryRef           string   `json:"delivery_ref,omitempty"`
	DeliveryError         string   `json:"delivery_error,omitempty"`
	AuthenticationMethods []string `json:"authentication_methods,omitempty"`
	Attempts              int      `json:"attempts,omitempty"`
	ExpiresAt             string   `json:"expires_at"`
	CreatedAt             string   `json:"created_at"`
}

type AuthActionAssuranceReceipt struct {
	Token       string   `json:"token"`
	WorkspaceID string   `json:"workspace_id"`
	UserID      string   `json:"user_id"`
	Methods     []string `json:"methods"`
	ExpiresAt   string   `json:"expires_at"`
}

const (
	AuthChallengePurposeLogin     = "login"
	AuthChallengePurposeLoginMFA  = "login_mfa"
	AuthChallengePurposeAction    = "action_assurance"
	AuthChallengeStatusPending    = "pending_delivery"
	AuthChallengeStatusActive     = "active"
	AuthChallengeStatusFailed     = "failed"
	AuthChallengeStatusConsumed   = "consumed"
	AuthChallengeStatusSuperseded = "superseded"
)

type AuthAuthorizationCode struct {
	Code           string      `json:"-"`
	WorkspaceID    string      `json:"workspace_id"`
	ApplicationKey string      `json:"application_key"`
	Session        AuthSession `json:"session"`
	RedirectURL    string      `json:"redirect_url"`
	ExpiresAt      string      `json:"expires_at"`
	CreatedAt      string      `json:"created_at"`
}

type AuthExternalIdentityAssertion struct {
	Provider    string            `json:"provider"`
	Subject     string            `json:"subject"`
	Email       string            `json:"email,omitempty"`
	Phone       string            `json:"phone,omitempty"`
	DisplayName string            `json:"display_name,omitempty"`
	AvatarURL   string            `json:"avatar_url,omitempty"`
	Metadata    string            `json:"metadata,omitempty"`
	Claims      map[string]string `json:"-"`

	// ProviderSubjectVerified is set only by server-side provider adapters after
	// they verify a stable subject with the upstream provider. It is never
	// accepted from transport JSON.
	ProviderSubjectVerified bool `json:"-"`
}

type AuthExternalLoginPolicy struct {
	AutoCreateUsers bool
	DefaultRoleKey  string
	RoleMappings    []AuthExternalRoleMapping
}

type AuthExternalRoleMapping struct {
	Claim   string
	Match   string
	RoleKey string
}
