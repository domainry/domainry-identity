package auth

import (
	"context"
	"regexp"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

var customAuthProviderKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)

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
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, identitycontract.IdentityActionAuthProvidersSetup) {
		return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindForbidden, "auth.permission_denied")
	}
	config, ok := s.Find(ctx, provider)
	newProvider := false
	if !ok {
		provider = strings.ToLower(strings.TrimSpace(provider))
		providerType := strings.ToLower(strings.TrimSpace(request.Type))
		if !customAuthProviderKeyPattern.MatchString(provider) || (providerType != "oidc" && providerType != "oauth2" && providerType != "saml") {
			return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindNotFound, "auth.provider_unknown")
		}
		label := strings.TrimSpace(request.Label)
		if label == "" {
			label = provider
		}
		config = authmodel.AuthProviderConfig{Key: provider, Label: label, Type: providerType}
		if providerType == "oauth2" {
			config.Adapter = "generic_oauth2"
		}
		newProvider = true
	}
	if strings.TrimSpace(request.Type) == "" {
		request.Type = config.Type
	}
	if !newProvider && !sameAuthProviderType(config.Key, config.Type, request.Type, request.Adapter) {
		return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindBadRequest, "auth.provider_type_change_not_allowed")
	}
	if strings.TrimSpace(request.Adapter) == "" {
		request.Adapter = config.Adapter
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
	if strings.EqualFold(request.Type, "otp") {
		if request.AllowedPurposes == nil {
			request.AllowedPurposes = append([]string(nil), config.AllowedPurposes...)
		}
		allowedPurposes, err := authmodel.NormalizeAuthProviderAllowedPurposes(request.AllowedPurposes)
		if err != nil {
			return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindBadRequest, "auth.provider_allowed_purposes_invalid")
		}
		request.AllowedPurposes = allowedPurposes
	} else if request.AllowedPurposes != nil {
		return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindBadRequest, "auth.provider_allowed_purposes_invalid")
	}
	if !configurableAuthProviderType(request.Type) {
		return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindBadRequest, "auth.provider_type_not_supported")
	}
	if s.credentials == nil {
		return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindInternal, "auth.provider_credential_writer_not_configured")
	}
	credential, err := s.credentials.UpsertAuthProviderCredential(ctx, provider, request, principal)
	if err != nil {
		return authmodel.AuthProviderConfig{}, err
	}
	authProviderApplyCredential(&config, credential)
	if newProvider {
		updated, added := s.AddConfig(config)
		if !added {
			return authmodel.AuthProviderConfig{}, authProviderApplicationError(apperror.KindConflict, "auth.provider_configuration_conflict")
		}
		return updated, nil
	}
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
	out := make([]map[string]any, 0, len(configs)+len(credentials))
	seen := map[string]bool{}
	for _, raw := range configs {
		config := authmodel.AuthProviderConfigFromMap(raw)
		key := strings.ToLower(strings.TrimSpace(config.Key))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		if value, ok := byKey[key]; ok {
			authProviderApplyCredential(&config, value)
		}
		out = append(out, config.Map())
	}
	for _, value := range credentials {
		key := strings.ToLower(strings.TrimSpace(value.ProviderKey))
		providerType := strings.ToLower(strings.TrimSpace(value.Type))
		if key == "" || seen[key] || !restorableAuthProviderType(providerType) {
			continue
		}
		label := strings.TrimSpace(value.Label)
		if label == "" {
			label = key
		}
		config := authmodel.AuthProviderConfig{Key: key, Label: label, Type: providerType}
		authProviderApplyCredential(&config, value)
		out = append(out, config.Map())
		seen[key] = true
	}
	return out
}

func restorableAuthProviderType(providerType string) bool {
	switch strings.ToLower(strings.TrimSpace(providerType)) {
	case "oidc", "oauth2", "saml", "otp", "code_exchange", "wechat_mini_program":
		return true
	default:
		return false
	}
}

func configurableAuthProviderType(providerType string) bool {
	switch strings.ToLower(strings.TrimSpace(providerType)) {
	case "oidc", "oauth2", "saml", "otp", "code_exchange", "wechat_mini_program":
		return true
	default:
		return false
	}
}

func sameAuthProviderType(providerKey, current, requested, adapter string) bool {
	providerKey = strings.ToLower(strings.TrimSpace(providerKey))
	current = strings.ToLower(strings.TrimSpace(current))
	requested = strings.ToLower(strings.TrimSpace(requested))
	adapter = strings.ToLower(strings.TrimSpace(adapter))
	return current == requested || current == "wechat_mini_program" && requested == "code_exchange" || providerKey == "line" && current == "oidc" && requested == "code_exchange" && adapter == "line_liff"
}

func authProviderApplyCredential(config *authmodel.AuthProviderConfig, value authmodel.AuthProviderCredential) {
	if value.Type != "" {
		config.Type = value.Type
	}
	if value.Adapter != "" {
		config.Adapter = value.Adapter
	}
	if value.Label != "" {
		config.Label = strings.TrimSpace(value.Label)
	}
	for target, candidate := range map[*string]string{
		&config.Issuer: value.Issuer, &config.AuthURL: value.AuthURL, &config.TokenURL: value.TokenURL,
		&config.UserInfoURL: value.UserInfoURL, &config.Scope: value.Scope,
	} {
		if strings.TrimSpace(candidate) != "" {
			*target = strings.TrimSpace(candidate)
		}
	}
	if strings.EqualFold(config.Type, "otp") {
		config.OTPProvider, config.ConnectionKey = strings.TrimSpace(value.OTPProvider), strings.TrimSpace(value.ConnectionKey)
		config.AllowedPurposes = append([]string(nil), value.AllowedPurposes...)
		config.Enabled = config.OTPProvider == "mock" || config.OTPProvider != "" && config.ConnectionKey != ""
	} else if strings.EqualFold(config.Type, "code_exchange") || strings.EqualFold(config.Type, "wechat_mini_program") {
		config.ClientID, config.ClientSecret, config.VerificationKey = value.ClientID, value.ClientSecret, value.VerificationKey
		config.ClientSecretConfigured = value.ClientSecret != ""
		config.VerificationKeyConfigured = value.VerificationKey != ""
		config.Enabled = config.ClientID != "" && (strings.EqualFold(config.Adapter, "line_liff") || config.ClientSecretConfigured) && (!strings.EqualFold(config.Adapter, "alipay_mini_program") || config.VerificationKeyConfigured)
	} else {
		config.ClientID, config.ClientSecret, config.RedirectURL = value.ClientID, value.ClientSecret, value.RedirectURL
		config.ClientSecretConfigured = value.ClientSecret != ""
		config.Enabled = config.ClientID != "" && config.ClientSecretConfigured && config.RedirectURL != ""
		if strings.EqualFold(config.Type, "oidc") && !strings.EqualFold(config.Key, "feishu") && !strings.EqualFold(config.Key, "lark") {
			config.Enabled = config.Enabled && config.Issuer != "" && config.AuthURL != ""
		}
		if strings.EqualFold(config.Type, "oauth2") {
			config.Enabled = config.Enabled && config.Adapter != "" && config.AuthURL != "" && config.TokenURL != "" && config.UserInfoURL != ""
		}
		if strings.EqualFold(config.Type, "saml") {
			config.Enabled = config.Enabled && config.AuthURL != ""
		}
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
