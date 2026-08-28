package service

import authprojection "github.com/domainry/domainry-identity/internal/domain/auth/projection"

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
)

// AuthProviderFlowDomainService coordinates provider authorization flows.
type AuthProviderFlowDomainService struct {
	auth      *AuthDomainService
	providers *AuthProviderDomainService
	writeback authcontract.AuthProviderExternalIdentityWriteback
}

func NewAuthProviderFlowDomainService(auth *AuthDomainService, providers *AuthProviderDomainService, writebacks ...authcontract.AuthProviderExternalIdentityWriteback) *AuthProviderFlowDomainService {
	service := &AuthProviderFlowDomainService{auth: auth, providers: providers}
	if len(writebacks) > 0 {
		service.writeback = writebacks[0]
	}
	return service
}
func (s *AuthProviderFlowDomainService) Start(ctx context.Context, workspaceID, provider, method, phone string) (authprojection.AuthProviderStartResponse, error) {
	return s.StartForApplication(ctx, workspaceID, provider, method, phone, "", "")
}

func (s *AuthProviderFlowDomainService) StartForApplication(ctx context.Context, workspaceID, provider, method, phone, applicationKey, returnURL string) (authprojection.AuthProviderStartResponse, error) {
	config, ok := s.providers.Enabled(ctx, provider)
	if !ok {
		return authprojection.AuthProviderStartResponse{}, forbidden("auth.provider_not_configured")
	}
	switch strings.ToLower(config.Type) {
	case "otp":
		if strings.ToUpper(method) != "POST" {
			return authprojection.AuthProviderStartResponse{}, badRequest("auth.provider_start_requires_post")
		}
		result, err := s.auth.BeginOTPLoginForApplication(ctx, workspaceID, provider, phone, applicationKey)
		if err == nil && config.OTPProvider != "mock" {
			result.Code = ""
		}
		return result, err
	case "saml":
		return s.auth.BeginSAMLLoginForApplication(ctx, workspaceID, provider, config.AuthURL, config.ClientID, config.RedirectURL, applicationKey, returnURL)
	case "oidc":
		return s.auth.BeginProviderLoginForApplication(ctx, workspaceID, provider, config.AuthURL, config.ClientID, config.RedirectURL, config.Scope, applicationKey, returnURL)
	case "oauth2":
		result, err := s.auth.BeginProviderLoginForApplication(ctx, workspaceID, provider, config.AuthURL, config.ClientID, config.RedirectURL, config.Scope, applicationKey, returnURL)
		if err == nil {
			result.AuthURL = adaptOAuth2ProviderAuthURL(result.AuthURL, config)
		}
		return result, err
	default:
		return authprojection.AuthProviderStartResponse{}, badRequest("auth.provider_start_not_supported")
	}
}

func adaptOAuth2ProviderAuthURL(raw string, config authmodel.AuthProviderConfig) string {
	adapter := strings.ToLower(strings.TrimSpace(config.Adapter))
	if adapter != "wechat_web" && adapter != "wecom" {
		return raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	query := parsed.Query()
	query.Set("appid", strings.TrimSpace(config.ClientID))
	query.Del("client_id")
	query.Del("nonce")
	query.Del("code_challenge")
	query.Del("code_challenge_method")
	parsed.RawQuery = query.Encode()
	parsed.Fragment = "wechat_redirect"
	return parsed.String()
}
func (s *AuthProviderFlowDomainService) VerifyOTP(ctx context.Context, workspaceID, provider, state, code string) (authmodel.AuthSession, error) {
	config, ok := s.providers.Enabled(ctx, provider)
	if !ok {
		return authmodel.AuthSession{}, forbidden("auth.provider_not_configured")
	}
	if config.Type != "otp" {
		return authmodel.AuthSession{}, badRequest("auth.provider_verify_not_supported")
	}
	assertion, applicationKey, err := s.auth.consumeOTPChallenge(ctx, workspaceID, provider, state, code)
	if err != nil {
		return authmodel.AuthSession{}, forbidden("auth.provider_state_invalid")
	}
	return s.auth.ExternalLoginWithPolicyForApplication(ctx, workspaceID, assertion, s.providers.AuthExternalLoginPolicy(ctx, config), applicationKey)
}
func (s *AuthProviderFlowDomainService) ExchangeCode(ctx context.Context, workspaceID, provider, code, applicationKey string, adapter authcontract.AuthProviderCodeExchangeAdapter) (authmodel.AuthSession, error) {
	config, ok := s.providers.Enabled(ctx, provider)
	if !ok {
		return authmodel.AuthSession{}, forbidden("auth.provider_not_configured")
	}
	if !strings.EqualFold(config.Type, "code_exchange") && !strings.EqualFold(config.Type, "wechat_mini_program") {
		return authmodel.AuthSession{}, badRequest("auth.provider_exchange_not_supported")
	}
	if strings.TrimSpace(code) == "" {
		return authmodel.AuthSession{}, badRequest("auth.provider_code_required")
	}
	assertion, err := adapter.ExchangeCode(ctx, provider, config, code)
	if err != nil {
		return authmodel.AuthSession{}, &apperror.AppError{Kind: apperror.KindUnavailable, Code: "auth.provider_code_exchange_failed", Err: err}
	}
	return s.CompleteCallbackForApplication(ctx, workspaceID, config, assertion, applicationKey)
}
func (s *AuthProviderFlowDomainService) ConsumeCallbackChallenge(ctx context.Context, provider, state string) (authmodel.AuthProviderConfig, authmodel.AuthProviderChallenge, error) {
	config, ok := s.providers.Enabled(ctx, provider)
	if !ok {
		return authmodel.AuthProviderConfig{}, authmodel.AuthProviderChallenge{}, forbidden("auth.provider_not_configured")
	}
	if config.Type != "oidc" && config.Type != "oauth2" && config.Type != "saml" {
		return authmodel.AuthProviderConfig{}, authmodel.AuthProviderChallenge{}, badRequest("auth.provider_callback_not_supported")
	}
	challenge, err := s.auth.ConsumeProviderChallenge(ctx, provider, state)
	if err == nil {
		if strings.TrimSpace(challenge.RedirectURL) != strings.TrimSpace(config.RedirectURL) {
			return authmodel.AuthProviderConfig{}, authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
		}
	}
	return config, challenge, err
}
func (s *AuthProviderFlowDomainService) CompleteCallback(ctx context.Context, workspaceID string, config authmodel.AuthProviderConfig, assertion authmodel.AuthExternalIdentityAssertion) (authmodel.AuthSession, error) {
	return s.CompleteCallbackForApplication(ctx, workspaceID, config, assertion, "")
}

func (s *AuthProviderFlowDomainService) CompleteCallbackForApplication(ctx context.Context, workspaceID string, config authmodel.AuthProviderConfig, assertion authmodel.AuthExternalIdentityAssertion, applicationKey string) (authmodel.AuthSession, error) {
	result, err := s.auth.ExternalLoginWithPolicyForApplication(ctx, workspaceID, assertion, s.providers.AuthExternalLoginPolicy(ctx, config), applicationKey)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if s.writeback != nil {
		if err := s.writeback.WriteAuthProviderExternalIdentity(ctx, assertion, result); err != nil {
			return authmodel.AuthSession{}, err
		}
	}
	return result, nil
}
func (s *AuthProviderFlowDomainService) ExchangeAndCompleteCallback(ctx context.Context, provider, state string, input authmodel.AuthProviderCallbackInput, adapter authcontract.AuthProviderCallbackAdapter) (authmodel.AuthSession, error) {
	result, _, err := s.ExchangeAndCompleteCallbackWithChallenge(ctx, provider, state, input, adapter)
	return result, err
}

func (s *AuthProviderFlowDomainService) ExchangeAndCompleteCallbackWithChallenge(ctx context.Context, provider, state string, input authmodel.AuthProviderCallbackInput, adapter authcontract.AuthProviderCallbackAdapter) (authmodel.AuthSession, authmodel.AuthProviderChallenge, error) {
	config, challenge, err := s.ConsumeCallbackChallenge(ctx, provider, state)
	if err != nil {
		return authmodel.AuthSession{}, authmodel.AuthProviderChallenge{}, err
	}
	assertion, err := adapter.Exchange(ctx, provider, config, challenge, input)
	if err != nil {
		return authmodel.AuthSession{}, challenge, err
	}
	if strings.EqualFold(config.Type, "saml") {
		claims := assertion.Claims
		assertionID, issuer, expiryText := strings.TrimSpace(claims["assertion_id"]), strings.TrimSpace(claims["issuer"]), strings.TrimSpace(claims["not_on_or_after"])
		expiresAt, parseErr := time.Parse(time.RFC3339Nano, expiryText)
		replays, supported := s.auth.identityStore.(authrepository.AuthAssertionReplayRepository)
		if parseErr != nil || assertionID == "" || issuer == "" || !supported {
			return authmodel.AuthSession{}, challenge, forbidden("auth.provider_assertion_invalid")
		}
		claimed, claimErr := replays.ClaimAuthAssertion(ctx, challenge.WorkspaceID, provider, issuer, assertionID, expiresAt)
		if claimErr != nil {
			return authmodel.AuthSession{}, challenge, claimErr
		}
		if !claimed {
			return authmodel.AuthSession{}, challenge, forbidden("auth.provider_assertion_replayed")
		}
	}
	result, err := s.CompleteCallbackForApplication(ctx, challenge.WorkspaceID, config, assertion, challenge.ApplicationKey)
	return result, challenge, err
}
