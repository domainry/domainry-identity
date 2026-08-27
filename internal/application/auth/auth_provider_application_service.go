package auth

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypolicy "github.com/domainry/domainry-identity/internal/domain/identity/policy"
)

type AuthProviderCredentialWriter interface {
	UpsertAuthProviderCredential(context.Context, string, authmodel.AuthProviderCredentialUpsertRequest, identitymodel.Principal) (authmodel.AuthProviderCredential, error)
}

type AuthProviderApplicationService struct {
	*authdomain.AuthProviderDomainService
	credentials AuthProviderCredentialWriter
}

func NewAuthProviderApplicationService(configs []map[string]any, defaultAutoCreate bool, credentials ...AuthProviderCredentialWriter) *AuthProviderApplicationService {
	service := &AuthProviderApplicationService{AuthProviderDomainService: authdomain.NewAuthProviderDomainService(configs, defaultAutoCreate)}
	if len(credentials) > 0 {
		service.credentials = credentials[0]
	}
	return service
}

func (s *AuthProviderApplicationService) SaveSetup(ctx context.Context, provider string, request authmodel.AuthProviderCredentialUpsertRequest, principal identitymodel.Principal) (authmodel.AuthProviderConfig, error) {
	if !principal.Known {
		return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindForbidden, "auth.token_required")
	}
	if _, err := identitymodel.NewWorkspaceCommandScope(principal.WorkspaceID); err != nil {
		return authmodel.AuthProviderConfig{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	if !identitypolicy.IdentityRoleHasPermissionKey(principal.Role, "workspace.admin") {
		return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindForbidden, "auth.permission_denied")
	}
	config, ok := s.Find(ctx, provider)
	if !ok {
		return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindNotFound, "auth.provider_unknown")
	}
	if strings.TrimSpace(request.Type) == "" {
		request.Type = config.Type
	}
	if strings.TrimSpace(request.RedirectURL) == "" {
		request.RedirectURL = config.RedirectURL
	}
	if strings.TrimSpace(request.Issuer) == "" {
		request.Issuer = config.Issuer
	}
	if strings.TrimSpace(request.AuthURL) == "" {
		request.AuthURL = config.AuthURL
	}
	if strings.TrimSpace(request.TokenURL) == "" {
		request.TokenURL = config.TokenURL
	}
	if strings.TrimSpace(request.UserInfoURL) == "" {
		request.UserInfoURL = config.UserInfoURL
	}
	if strings.TrimSpace(request.Scope) == "" {
		request.Scope = config.Scope
	}
	if s.credentials == nil {
		return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindInternal, "auth.provider_credential_writer_not_configured")
	}
	credential, err := s.credentials.UpsertAuthProviderCredential(ctx, provider, request, principal)
	if err != nil {
		return authmodel.AuthProviderConfig{}, err
	}
	authProviderApplyCredential(&config, credential)
	updated, ok := s.ReplaceConfig(config)
	if !ok {
		return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindNotFound, "auth.provider_unknown")
	}
	return updated, nil
}

func MergeTypedAuthProviderCredentials(configs []map[string]any, credentials []authmodel.AuthProviderCredential) []map[string]any {
	byKey := map[string]authmodel.AuthProviderCredential{}
	for _, value := range credentials {
		byKey[strings.ToLower(strings.TrimSpace(value.ProviderKey))] = value
	}
	out := make([]map[string]any, 0, len(configs))
	for _, raw := range configs {
		config := authmodel.AuthProviderConfigFromMap(raw)
		if value, ok := byKey[strings.ToLower(config.Key)]; ok {
			authProviderApplyCredential(&config, value)
		}
		out = append(out, config.Map())
	}
	return out
}

func authProviderApplyCredential(config *authmodel.AuthProviderConfig, value authmodel.AuthProviderCredential) {
	if value.Type != "" {
		config.Type = value.Type
	}
	if strings.EqualFold(config.Type, "otp") {
		config.OTPProvider, config.AccessToken, config.PhoneNumberID = value.OTPProvider, value.AccessToken, value.PhoneNumberID
		config.AccessTokenConfigured = value.AccessToken != ""
		config.PhoneNumberIDConfigured = value.PhoneNumberID != ""
		config.Enabled = config.OTPProvider != "" && config.AccessTokenConfigured && config.PhoneNumberIDConfigured
	} else {
		config.ClientID, config.ClientSecret, config.RedirectURL = value.ClientID, value.ClientSecret, value.RedirectURL
		config.ClientSecretConfigured = value.ClientSecret != ""
		config.Enabled = config.ClientID != "" && config.ClientSecretConfigured && config.RedirectURL != ""
	}
	config.AutoCreateUsers, config.AutoCreateConfigured, config.DefaultRoleKey = value.AutoCreateUsers, true, value.DefaultRoleKey
	config.RoleMappings = make([]authmodel.AuthExternalRoleMapping, 0, len(value.RoleMappings))
	for _, mapping := range value.RoleMappings {
		config.RoleMappings = append(config.RoleMappings, authmodel.AuthExternalRoleMapping{Claim: mapping.Claim, Match: mapping.Match, RoleKey: mapping.RoleKey})
	}
	config.ConfiguredFrom, config.UpdatedAt = "setup", value.UpdatedAt
}

func authProviderApplicationError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}
