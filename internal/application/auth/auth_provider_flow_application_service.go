package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type AuthenticationAuditRequest struct {
	IdempotencyKey string
	Event          string
	ObjectKey      string
	RecordID       string
	Principal      identitymodel.Principal
	Summary        string
	Metadata       map[string]any
}

type AuthenticationAuditAppender func(context.Context, AuthenticationAuditRequest) error

type AuthProviderFlowApplicationService struct {
	*authdomain.AuthProviderFlowDomainService
	auth                *AuthApplicationService
	audit               AuthenticationAuditAppender
	loginFingerprintKey []byte
}

func NewAuthProviderFlowApplicationService(auth *AuthApplicationService, providers *AuthProviderApplicationService, writebacks ...authcontract.AuthProviderExternalIdentityWriteback) *AuthProviderFlowApplicationService {
	var owner *authdomain.AuthDomainService
	var fingerprintKey []byte
	if auth != nil {
		owner = auth.AuthDomainService
		fingerprintKey = append([]byte(nil), auth.pepper...)
	}
	var providerOwner *authdomain.AuthProviderDomainService
	if providers != nil {
		providerOwner = providers.AuthProviderDomainService
	}
	return &AuthProviderFlowApplicationService{
		AuthProviderFlowDomainService: authdomain.NewAuthProviderFlowDomainService(owner, providerOwner, writebacks...),
		auth:                          auth,
		loginFingerprintKey:           fingerprintKey,
	}
}

func (s *AuthProviderFlowApplicationService) ConfigureAuthenticationAudit(appender AuthenticationAuditAppender) {
	if s != nil {
		s.audit = appender
	}
}

func (s *AuthProviderFlowApplicationService) LoginWithPasswordOutcome(ctx context.Context, workspaceID, login, password, applicationKey string) (authmodel.AuthenticationOutcome, error) {
	outcome, err := s.AuthProviderFlowDomainService.LoginWithPasswordOutcome(ctx, workspaceID, login, password, applicationKey)
	if err != nil {
		if auditErr := s.appendAuthenticationFailure(ctx, workspaceID, "password", "", applicationKey, login, "invalid_credentials", "auth.invalid_credentials"); auditErr != nil {
			return authmodel.AuthenticationOutcome{}, auditErr
		}
		return outcome, err
	}
	if outcome.Status != authmodel.AuthenticationStatusAuthenticated || outcome.Session == nil {
		return outcome, nil
	}
	if auditErr := s.appendAuthenticationSuccess(ctx, "password", "", applicationKey, *outcome.Session); auditErr != nil {
		s.revokeUnauditedSession(ctx, *outcome.Session)
		return authmodel.AuthenticationOutcome{}, auditErr
	}
	return outcome, nil
}

func (s *AuthProviderFlowApplicationService) VerifyOTPOutcome(ctx context.Context, workspaceID, provider, state, code string) (authmodel.AuthenticationOutcome, error) {
	outcome, err := s.AuthProviderFlowDomainService.VerifyOTPOutcome(ctx, workspaceID, provider, state, code)
	if err != nil {
		if auditErr := s.appendAuthenticationFailure(ctx, workspaceID, "otp", provider, "", "", "authentication_failed", authenticationErrorCode(err)); auditErr != nil {
			return authmodel.AuthenticationOutcome{}, auditErr
		}
		return outcome, err
	}
	if outcome.Status != authmodel.AuthenticationStatusAuthenticated || outcome.Session == nil {
		return outcome, nil
	}
	if auditErr := s.appendAuthenticationSuccess(ctx, "otp", provider, authenticationApplicationKey(ctx, s.auth, *outcome.Session), *outcome.Session); auditErr != nil {
		s.revokeUnauditedSession(ctx, *outcome.Session)
		return authmodel.AuthenticationOutcome{}, auditErr
	}
	return outcome, nil
}

func (s *AuthProviderFlowApplicationService) VerifyOTP(ctx context.Context, workspaceID, provider, state, code string) (authmodel.AuthSession, error) {
	outcome, err := s.VerifyOTPOutcome(ctx, workspaceID, provider, state, code)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if outcome.Session == nil {
		return authmodel.AuthSession{}, apperror.New(apperror.KindForbidden, "auth.provider_state_invalid", nil, nil)
	}
	return *outcome.Session, nil
}

func (s *AuthProviderFlowApplicationService) ExchangeCode(ctx context.Context, workspaceID, provider, code, applicationKey string, adapter authcontract.AuthProviderCodeExchangeAdapter) (authmodel.AuthSession, error) {
	session, err := s.AuthProviderFlowDomainService.ExchangeCode(ctx, workspaceID, provider, code, applicationKey, adapter)
	if err != nil {
		if auditErr := s.appendAuthenticationFailure(ctx, workspaceID, "provider", provider, applicationKey, "", "authentication_failed", authenticationErrorCode(err)); auditErr != nil {
			return authmodel.AuthSession{}, auditErr
		}
		return session, err
	}
	if auditErr := s.appendAuthenticationSuccess(ctx, "provider", provider, applicationKey, session); auditErr != nil {
		s.revokeUnauditedSession(ctx, session)
		return authmodel.AuthSession{}, auditErr
	}
	return session, nil
}

func (s *AuthProviderFlowApplicationService) ExchangeAndCompleteCallbackWithChallenge(ctx context.Context, workspaceID, provider, state string, input authmodel.AuthProviderCallbackInput, adapter authcontract.AuthProviderCallbackAdapter) (authmodel.AuthSession, authmodel.AuthProviderChallenge, error) {
	session, challenge, err := s.AuthProviderFlowDomainService.ExchangeAndCompleteCallbackWithChallenge(ctx, workspaceID, provider, state, input, adapter)
	if err != nil {
		if auditErr := s.appendAuthenticationFailure(ctx, workspaceID, "provider", provider, challenge.ApplicationKey, "", "authentication_failed", authenticationErrorCode(err)); auditErr != nil {
			return authmodel.AuthSession{}, authmodel.AuthProviderChallenge{}, auditErr
		}
		return session, challenge, err
	}
	if auditErr := s.appendAuthenticationSuccess(ctx, "provider", provider, challenge.ApplicationKey, session); auditErr != nil {
		s.revokeUnauditedSession(ctx, session)
		return authmodel.AuthSession{}, authmodel.AuthProviderChallenge{}, auditErr
	}
	return session, challenge, nil
}

func (s *AuthProviderFlowApplicationService) appendAuthenticationSuccess(ctx context.Context, method, provider, applicationKey string, session authmodel.AuthSession) error {
	requestID, ctx := authenticationRequestID(ctx)
	principal := identitymodel.Principal{
		Known: true, WorkspaceID: session.WorkspaceID, UserID: session.User.ID,
		Role: identitymodel.RoleSchema{Key: session.DefaultRole}, RequestID: requestID, CorrelationID: requestcontext.CorrelationID(ctx),
	}
	return s.appendAuthenticationAudit(ctx, AuthenticationAuditRequest{
		IdempotencyKey: authenticationAuditIdempotencyKey("auth_login_succeeded", requestID),
		Event:          "auth_login_succeeded", ObjectKey: "identity_login", RecordID: session.User.ID,
		Principal: principal, Summary: "Authentication succeeded",
		Metadata: authenticationMetadata(method, provider, applicationKey, "success", "authentication_completed", ""),
	})
}

func (s *AuthProviderFlowApplicationService) appendAuthenticationFailure(ctx context.Context, workspaceID, method, provider, applicationKey, login, reason, errorCode string) error {
	requestID, ctx := authenticationRequestID(ctx)
	metadata := authenticationMetadata(method, provider, applicationKey, "failed", reason, errorCode)
	if fingerprint := s.loginFingerprint(login); fingerprint != "" {
		metadata["login_fingerprint_sha256"] = fingerprint
	}
	return s.appendAuthenticationAudit(ctx, AuthenticationAuditRequest{
		IdempotencyKey: authenticationAuditIdempotencyKey("auth_login_failed", requestID),
		Event:          "auth_login_failed", ObjectKey: "identity_login",
		Principal: identitymodel.Principal{
			WorkspaceID: strings.TrimSpace(workspaceID), UserID: "anonymous", RequestID: requestID,
			Role: identitymodel.RoleSchema{Key: "anonymous"}, CorrelationID: requestcontext.CorrelationID(ctx), Known: false,
		},
		Summary: "Authentication failed", Metadata: metadata,
	})
}

func (s *AuthProviderFlowApplicationService) appendAuthenticationAudit(ctx context.Context, request AuthenticationAuditRequest) error {
	if s == nil || s.audit == nil {
		return nil
	}
	if err := s.audit(ctx, request); err != nil {
		return apperror.New(apperror.KindInternal, "backend.audit.append_failed", err, nil)
	}
	return nil
}

func (s *AuthProviderFlowApplicationService) loginFingerprint(login string) string {
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" || len(s.loginFingerprintKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, s.loginFingerprintKey)
	_, _ = mac.Write([]byte(login))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *AuthProviderFlowApplicationService) revokeUnauditedSession(ctx context.Context, session authmodel.AuthSession) {
	if s == nil || s.auth == nil || strings.TrimSpace(session.RefreshToken) == "" {
		return
	}
	s.auth.Logout(ctx, session.WorkspaceID, session.RefreshToken)
}

func authenticationMetadata(method, provider, applicationKey, result, reason, errorCode string) map[string]any {
	metadata := map[string]any{"authentication_method": strings.TrimSpace(method), "result": strings.TrimSpace(result)}
	if provider = strings.TrimSpace(provider); provider != "" {
		metadata["provider"] = provider
	}
	if applicationKey = strings.TrimSpace(applicationKey); applicationKey != "" {
		metadata["application_key"] = applicationKey
	}
	if reason = strings.TrimSpace(reason); reason != "" {
		metadata["reason"] = reason
	}
	if errorCode = strings.TrimSpace(errorCode); errorCode != "" {
		metadata["error_code"] = errorCode
	}
	return metadata
}

func authenticationRequestID(ctx context.Context) (string, context.Context) {
	requestID := requestcontext.RequestID(ctx)
	if requestID == "" {
		requestID = requestcontext.NewRequestID()
		ctx = requestcontext.WithRequestID(ctx, requestID)
	}
	return requestID, ctx
}

func authenticationAuditIdempotencyKey(event, requestID string) string {
	if requestID = strings.TrimSpace(requestID); requestID != "" {
		return strings.TrimSpace(event) + ":" + requestID
	}
	return ""
}

func authenticationApplicationKey(ctx context.Context, auth *AuthApplicationService, session authmodel.AuthSession) string {
	if auth == nil || strings.TrimSpace(session.AccessToken) == "" {
		return ""
	}
	claims, err := auth.VerifyAccessToken(ctx, session.AccessToken)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(claims.Audience)
}

func authenticationErrorCode(err error) string {
	if code := strings.TrimSpace(apperror.CodeOf(err)); code != "" {
		return code
	}
	return "auth.authentication_failed"
}
