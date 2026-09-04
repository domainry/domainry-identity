package service

import authprojection "github.com/domainry/domainry-identity/internal/domain/auth/projection"

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// AuthProviderFlowDomainService coordinates provider authorization flows.
type AuthProviderFlowDomainService struct {
	auth      *AuthDomainService
	providers *AuthProviderDomainService
	writeback authcontract.AuthProviderExternalIdentityWriteback
	delivery  authcontract.AuthSecurityChallengeDelivery
}

func (s *AuthProviderFlowDomainService) UseSecurityChallengeDelivery(delivery authcontract.AuthSecurityChallengeDelivery) {
	s.delivery = delivery
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
		if !config.SupportsChallengePurpose(authmodel.AuthChallengePurposeLogin) {
			return authprojection.AuthProviderStartResponse{}, forbidden("auth.provider_purpose_not_enabled")
		}
		if strings.ToUpper(method) != "POST" {
			return authprojection.AuthProviderStartResponse{}, badRequest("auth.provider_start_requires_post")
		}
		result, err := s.auth.BeginOTPChallenge(ctx, workspaceID, provider, phone, applicationKey, authmodel.AuthChallengePurposeLogin, "", nil)
		if err != nil {
			return authprojection.AuthProviderStartResponse{}, err
		}
		return s.deliverOTPChallenge(ctx, workspaceID, config, phone, result)
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

func (s *AuthProviderFlowDomainService) LoginWithPasswordOutcome(ctx context.Context, workspaceID, login, password, applicationKey string) (authmodel.AuthenticationOutcome, error) {
	user, err := s.auth.AuthenticatePassword(ctx, workspaceID, login, password)
	if err != nil {
		return authmodel.AuthenticationOutcome{}, err
	}
	repository, mfaAvailable := s.auth.identityStore.(authrepository.AuthMFARepository)
	if !mfaAvailable {
		session, err := s.auth.issueSessionForAudienceWithAuthentication(ctx, workspaceID, user, applicationKey, passwordAuthenticationContext())
		return authenticatedOutcome(session), err
	}
	factors, err := repository.ListIdentityMFAFactors(ctx, workspaceID, user.ID)
	if err != nil {
		return authmodel.AuthenticationOutcome{}, err
	}
	active := make([]identitymodel.IdentityMFAFactor, 0, len(factors))
	for _, factor := range factors {
		if strings.EqualFold(strings.TrimSpace(factor.Status), "active") && strings.TrimSpace(factor.VerifiedAt) != "" {
			active = append(active, factor)
		}
	}
	if len(active) == 0 {
		session, err := s.auth.issueSessionForAudienceWithAuthentication(ctx, workspaceID, user, applicationKey, passwordAuthenticationContext())
		return authenticatedOutcome(session), err
	}
	config, required, available := s.verifiedOTPProviderForPurpose(ctx, active, authmodel.AuthChallengePurposeLoginMFA)
	if !required {
		session, err := s.auth.issueSessionForAudienceWithAuthentication(ctx, workspaceID, user, applicationKey, passwordAuthenticationContext())
		return authenticatedOutcome(session), err
	}
	if !available || strings.TrimSpace(user.Phone) == "" {
		return authmodel.AuthenticationOutcome{}, forbidden("auth.mfa_factor_unavailable")
	}
	result, err := s.auth.BeginOTPChallenge(ctx, workspaceID, config.Key, user.Phone, applicationKey, authmodel.AuthChallengePurposeLoginMFA, user.ID, []string{"pwd"})
	if err != nil {
		return authmodel.AuthenticationOutcome{}, err
	}
	result, err = s.deliverOTPChallenge(ctx, workspaceID, config, user.Phone, result)
	if err != nil {
		return authmodel.AuthenticationOutcome{}, err
	}
	challenge := authProviderChallengeFromProjection(result)
	return authmodel.AuthenticationOutcome{Status: authmodel.AuthenticationStatusChallengeRequired, Challenge: &challenge}, nil
}

func (s *AuthProviderFlowDomainService) VerifyOTPOutcome(ctx context.Context, workspaceID, provider, state, code string) (authmodel.AuthenticationOutcome, error) {
	config, ok := s.providers.Enabled(ctx, provider)
	if !ok {
		return authmodel.AuthenticationOutcome{}, forbidden("auth.provider_not_configured")
	}
	if config.Type != "otp" {
		return authmodel.AuthenticationOutcome{}, badRequest("auth.provider_verify_not_supported")
	}
	assertion, challenge, err := s.auth.consumeOTPChallenge(ctx, workspaceID, provider, state, code, []string{authmodel.AuthChallengePurposeLogin, authmodel.AuthChallengePurposeLoginMFA}, "")
	if err != nil {
		return authmodel.AuthenticationOutcome{}, err
	}
	var session authmodel.AuthSession
	switch challenge.Purpose {
	case authmodel.AuthChallengePurposeLoginMFA:
		user, found, loadErr := s.auth.identity.UserByID(ctx, challenge.UserID)
		if loadErr != nil {
			return authmodel.AuthenticationOutcome{}, loadErr
		}
		if !found || user.Status != identitymodel.IdentityStatusActive {
			return authmodel.AuthenticationOutcome{}, forbidden("auth.user_disabled")
		}
		methods := append(append([]string(nil), challenge.AuthenticationMethods...), "otp")
		session, err = s.auth.issueSessionForAudienceWithAuthentication(ctx, workspaceID, user, challenge.ApplicationKey, authmodel.AuthenticationContext{Methods: methods, AssuranceLevel: "urn:domainry:acr:2"})
	case authmodel.AuthChallengePurposeLogin:
		session, err = s.auth.ExternalLoginWithPolicyForApplicationAndAuthentication(ctx, workspaceID, assertion, s.providers.AuthExternalLoginPolicy(ctx, config), challenge.ApplicationKey, authmodel.AuthenticationContext{Methods: []string{"otp"}, AssuranceLevel: "urn:domainry:acr:1"})
	default:
		return authmodel.AuthenticationOutcome{}, forbidden("auth.provider_state_invalid")
	}
	return authenticatedOutcome(session), err
}

func (s *AuthProviderFlowDomainService) BeginActionAssurance(ctx context.Context, workspaceID, userID string) (authprojection.AuthProviderStartResponse, error) {
	user, found, err := s.auth.identity.UserByID(requestcontext.WithWorkspaceID(ctx, workspaceID), strings.TrimSpace(userID))
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	if !found || user.Status != identitymodel.IdentityStatusActive {
		return authprojection.AuthProviderStartResponse{}, forbidden("auth.user_disabled")
	}
	if strings.TrimSpace(user.Phone) == "" {
		return authprojection.AuthProviderStartResponse{}, forbidden("auth.mfa_factor_unavailable")
	}
	repository, ok := s.auth.identityStore.(authrepository.AuthMFARepository)
	if !ok {
		return authprojection.AuthProviderStartResponse{}, forbidden("auth.mfa_factor_unavailable")
	}
	factors, err := repository.ListIdentityMFAFactors(ctx, workspaceID, user.ID)
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	config, required, available := s.verifiedOTPProviderForPurpose(ctx, factors, authmodel.AuthChallengePurposeAction)
	if !required || !available {
		return authprojection.AuthProviderStartResponse{}, forbidden("auth.mfa_factor_unavailable")
	}
	result, err := s.auth.BeginOTPChallenge(ctx, workspaceID, config.Key, user.Phone, "", authmodel.AuthChallengePurposeAction, user.ID, nil)
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	return s.deliverOTPChallenge(ctx, workspaceID, config, user.Phone, result)
}

func (s *AuthProviderFlowDomainService) verifiedOTPProviderForPurpose(ctx context.Context, factors []identitymodel.IdentityMFAFactor, purpose string) (authmodel.AuthProviderConfig, bool, bool) {
	unboundEligible := false
	for _, factor := range factors {
		factorType := strings.ToLower(strings.TrimSpace(factor.Type))
		if !strings.EqualFold(strings.TrimSpace(factor.Status), "active") || strings.TrimSpace(factor.VerifiedAt) == "" || factorType != "otp" && factorType != "sms" && factorType != "external" {
			continue
		}
		providerKey := strings.TrimSpace(factor.Provider)
		if providerKey == "" {
			unboundEligible = true
			continue
		}
		candidate, configured := s.providers.Find(ctx, providerKey)
		if !configured || !strings.EqualFold(candidate.Type, "otp") {
			unboundEligible = true
			continue
		}
		if !candidate.SupportsChallengePurpose(purpose) {
			continue
		}
		if candidate.Enabled {
			return candidate, true, true
		}
		return authmodel.AuthProviderConfig{}, true, false
	}
	if unboundEligible {
		candidate, configured := s.providers.FirstByTypeAndPurpose("otp", purpose)
		if configured {
			return candidate, true, candidate.Enabled
		}
	}
	return authmodel.AuthProviderConfig{}, false, false
}

func (s *AuthProviderFlowDomainService) VerifyActionAssurance(ctx context.Context, workspaceID, userID, provider, state, code string) (authmodel.AuthActionAssuranceReceipt, error) {
	config, ok := s.providers.Enabled(ctx, provider)
	if !ok || !strings.EqualFold(config.Type, "otp") {
		return authmodel.AuthActionAssuranceReceipt{}, forbidden("auth.provider_not_configured")
	}
	_, challenge, err := s.auth.consumeOTPChallenge(ctx, workspaceID, provider, state, code, []string{authmodel.AuthChallengePurposeAction}, strings.TrimSpace(userID))
	if err != nil {
		return authmodel.AuthActionAssuranceReceipt{}, err
	}
	if challenge.Purpose != authmodel.AuthChallengePurposeAction || challenge.UserID != strings.TrimSpace(userID) {
		return authmodel.AuthActionAssuranceReceipt{}, forbidden("auth.action_assurance_challenge_invalid")
	}
	return s.auth.IssueActionAssuranceReceipt(ctx, challenge)
}

func (s *AuthProviderFlowDomainService) deliverOTPChallenge(ctx context.Context, workspaceID string, config authmodel.AuthProviderConfig, phone string, result authprojection.AuthProviderStartResponse) (authprojection.AuthProviderStartResponse, error) {
	if strings.EqualFold(strings.TrimSpace(config.OTPProvider), "mock") {
		if err := s.auth.UpdateOTPChallengeDelivery(ctx, workspaceID, config.Key, result.State, authmodel.AuthChallengeStatusActive, "mock", ""); err != nil {
			return authprojection.AuthProviderStartResponse{}, err
		}
		result.Status = authmodel.AuthChallengeStatusActive
		return result, nil
	}
	if s.delivery == nil || strings.TrimSpace(config.ConnectionKey) == "" {
		_ = s.auth.UpdateOTPChallengeDelivery(ctx, workspaceID, config.Key, result.State, authmodel.AuthChallengeStatusFailed, "", "delivery unavailable")
		return authprojection.AuthProviderStartResponse{}, &apperror.AppError{Kind: apperror.KindUnavailable, Code: "auth.otp_delivery_unavailable"}
	}
	receipt, err := s.delivery.DeliverSecurityChallenge(ctx, authcontract.AuthSecurityChallengeDeliveryRequest{
		ChallengeID: result.State, WorkspaceID: workspaceID, ConnectionKey: config.ConnectionKey, Channel: config.OTPProvider,
		Destination: phone, MaskedDestination: result.MaskedDestination, Message: "Your Domainry verification code is " + result.Code + ". It expires in 10 minutes.", ExpiresAt: result.ExpiresAt,
	})
	if err != nil {
		// Provider errors are untrusted and may echo request fields. Persist only a
		// stable non-sensitive reason; the returned error still carries operational
		// detail for request-scoped logging at the owning boundary.
		_ = s.auth.UpdateOTPChallengeDelivery(ctx, workspaceID, config.Key, result.State, authmodel.AuthChallengeStatusFailed, receipt.ResponseRef, "delivery failed")
		return authprojection.AuthProviderStartResponse{}, &apperror.AppError{Kind: apperror.KindUnavailable, Code: "auth.otp_delivery_failed"}
	}
	if err := s.auth.UpdateOTPChallengeDelivery(ctx, workspaceID, config.Key, result.State, authmodel.AuthChallengeStatusActive, receipt.ResponseRef, ""); err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	result.Status, result.Code = authmodel.AuthChallengeStatusActive, ""
	return result, nil
}

func authenticatedOutcome(session authmodel.AuthSession) authmodel.AuthenticationOutcome {
	if strings.TrimSpace(session.AccessToken) == "" {
		return authmodel.AuthenticationOutcome{}
	}
	copy := session
	return authmodel.AuthenticationOutcome{Status: authmodel.AuthenticationStatusAuthenticated, Session: &copy}
}

func authProviderChallengeFromProjection(value authprojection.AuthProviderStartResponse) authmodel.AuthProviderChallenge {
	return authmodel.AuthProviderChallenge{Provider: value.Provider, State: value.State, Type: value.Type, Purpose: value.Purpose, Status: value.Status, MaskedDestination: value.MaskedDestination, RetryAt: value.RetryAt, ExpiresAt: value.ExpiresAt}
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
	outcome, err := s.VerifyOTPOutcome(ctx, workspaceID, provider, state, code)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if outcome.Session == nil {
		return authmodel.AuthSession{}, forbidden("auth.provider_state_invalid")
	}
	return *outcome.Session, nil
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
func (s *AuthProviderFlowDomainService) ConsumeCallbackChallenge(ctx context.Context, workspaceID, provider, state string) (authmodel.AuthProviderConfig, authmodel.AuthProviderChallenge, error) {
	config, ok := s.providers.Enabled(ctx, provider)
	if !ok {
		return authmodel.AuthProviderConfig{}, authmodel.AuthProviderChallenge{}, forbidden("auth.provider_not_configured")
	}
	if config.Type != "oidc" && config.Type != "oauth2" && config.Type != "saml" {
		return authmodel.AuthProviderConfig{}, authmodel.AuthProviderChallenge{}, badRequest("auth.provider_callback_not_supported")
	}
	challenge, err := s.auth.ConsumeProviderChallenge(ctx, workspaceID, provider, state)
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
func (s *AuthProviderFlowDomainService) ExchangeAndCompleteCallback(ctx context.Context, workspaceID, provider, state string, input authmodel.AuthProviderCallbackInput, adapter authcontract.AuthProviderCallbackAdapter) (authmodel.AuthSession, error) {
	result, _, err := s.ExchangeAndCompleteCallbackWithChallenge(ctx, workspaceID, provider, state, input, adapter)
	return result, err
}

func (s *AuthProviderFlowDomainService) ExchangeAndCompleteCallbackWithChallenge(ctx context.Context, workspaceID, provider, state string, input authmodel.AuthProviderCallbackInput, adapter authcontract.AuthProviderCallbackAdapter) (authmodel.AuthSession, authmodel.AuthProviderChallenge, error) {
	config, challenge, err := s.ConsumeCallbackChallenge(ctx, workspaceID, provider, state)
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
