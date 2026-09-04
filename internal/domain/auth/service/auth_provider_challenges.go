package service

import authprojection "github.com/domainry/domainry-identity/internal/domain/auth/projection"

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *AuthDomainService) BeginProviderLogin(ctx context.Context, workspaceID, provider string, authURL string, clientID string, redirectURL string, scope string) (authprojection.AuthProviderStartResponse, error) {
	return s.BeginProviderLoginForApplication(ctx, workspaceID, provider, authURL, clientID, redirectURL, scope, "", "")
}

func (s *AuthDomainService) BeginProviderLoginForApplication(ctx context.Context, workspaceID, provider string, authURL string, clientID string, redirectURL string, scope string, applicationKey string, returnURL string) (authprojection.AuthProviderStartResponse, error) {
	if err := ctx.Err(); err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	provider = normalizeProvider(provider)
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	workspaceID = workspace.String()
	if provider == "" || provider == "local" {
		return authprojection.AuthProviderStartResponse{}, badRequest("auth.provider_invalid")
	}
	state, err := s.randomToken()
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, internalError("generate provider state", err)
	}
	nonce, err := s.randomToken()
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, internalError("generate provider nonce", err)
	}
	verifierFirst, err := s.randomToken()
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, internalError("generate PKCE verifier", err)
	}
	verifierSecond, err := s.randomToken()
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, internalError("generate PKCE verifier", err)
	}
	codeVerifier := verifierFirst + verifierSecond
	codeChallengeDigest := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeDigest[:])
	now := time.Now().UTC()
	expiresAt := now.Add(10 * time.Minute)
	challenge := authmodel.AuthProviderChallenge{
		WorkspaceID:    workspaceID,
		ApplicationKey: strings.TrimSpace(applicationKey),
		Provider:       provider,
		RedirectURL:    strings.TrimSpace(redirectURL),
		State:          state,
		Nonce:          nonce,
		CodeVerifier:   codeVerifier,
		ReturnURL:      strings.TrimSpace(returnURL),
		ExpiresAt:      expiresAt.Format(time.RFC3339),
		CreatedAt:      now.Format(time.RFC3339),
	}
	if transactions, ok := s.identityStore.(authrepository.AuthLoginTransactionRepository); ok {
		if err := transactions.CreateAuthLoginTransaction(ctx, challenge); err != nil {
			return authprojection.AuthProviderStartResponse{}, err
		}
	} else {
		s.challengeMu.Lock()
		s.challenges[state] = challenge
		s.challengeMu.Unlock()
	}
	return authprojection.AuthProviderStartResponse{
		Provider:  provider,
		State:     state,
		Nonce:     nonce,
		AuthURL:   buildProviderAuthURL(authURL, clientID, redirectURL, scope, state, nonce, codeChallenge),
		ExpiresAt: challenge.ExpiresAt,
	}, nil
}

func (s *AuthDomainService) BeginSAMLLogin(ctx context.Context, workspaceID, provider string, ssoURL string, entityID string, acsURL string) (authprojection.AuthProviderStartResponse, error) {
	return s.BeginSAMLLoginForApplication(ctx, workspaceID, provider, ssoURL, entityID, acsURL, "", "")
}

func (s *AuthDomainService) BeginSAMLLoginForApplication(ctx context.Context, workspaceID, provider string, ssoURL string, entityID string, acsURL string, applicationKey string, returnURL string) (authprojection.AuthProviderStartResponse, error) {
	if err := ctx.Err(); err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	provider = normalizeProvider(provider)
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	workspaceID = workspace.String()
	if provider == "" || provider == "local" {
		return authprojection.AuthProviderStartResponse{}, badRequest("auth.provider_invalid")
	}
	state, err := s.randomToken()
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, internalError("generate provider state", err)
	}
	requestID, err := s.randomToken()
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, internalError("generate SAML request identifier", err)
	}
	now := time.Now().UTC()
	expiresAt := now.Add(10 * time.Minute)
	challenge := authmodel.AuthProviderChallenge{
		WorkspaceID:    workspaceID,
		ApplicationKey: strings.TrimSpace(applicationKey),
		Provider:       provider,
		RedirectURL:    strings.TrimSpace(acsURL),
		State:          state,
		RequestID:      "_" + requestID,
		ReturnURL:      strings.TrimSpace(returnURL),
		ExpiresAt:      expiresAt.Format(time.RFC3339),
		CreatedAt:      now.Format(time.RFC3339),
	}
	if transactions, ok := s.identityStore.(authrepository.AuthLoginTransactionRepository); ok {
		if err := transactions.CreateAuthLoginTransaction(ctx, challenge); err != nil {
			return authprojection.AuthProviderStartResponse{}, err
		}
	} else {
		s.challengeMu.Lock()
		s.challenges[state] = challenge
		s.challengeMu.Unlock()
	}
	return authprojection.AuthProviderStartResponse{
		Provider:  provider,
		State:     state,
		AuthURL:   buildSAMLProviderAuthURL(ssoURL, entityID, acsURL, state, challenge.RequestID),
		ExpiresAt: challenge.ExpiresAt,
	}, nil
}

func (s *AuthDomainService) BeginOTPLogin(ctx context.Context, workspaceID, provider string, phone string) (authprojection.AuthProviderStartResponse, error) {
	return s.BeginOTPLoginForApplication(ctx, workspaceID, provider, phone, "")
}

func (s *AuthDomainService) BeginOTPLoginForApplication(ctx context.Context, workspaceID, provider string, phone string, applicationKey string) (authprojection.AuthProviderStartResponse, error) {
	result, err := s.BeginOTPChallenge(ctx, workspaceID, provider, phone, applicationKey, authmodel.AuthChallengePurposeLogin, "", nil)
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	if err := s.UpdateOTPChallengeDelivery(ctx, workspaceID, provider, result.State, authmodel.AuthChallengeStatusActive, "local", ""); err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	result.Status = authmodel.AuthChallengeStatusActive
	return result, nil
}

func (s *AuthDomainService) BeginOTPChallenge(ctx context.Context, workspaceID, provider, phone, applicationKey, purpose, userID string, authenticationMethods []string) (authprojection.AuthProviderStartResponse, error) {
	if err := ctx.Err(); err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	provider = normalizeProvider(provider)
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	workspaceID = workspace.String()
	phone, err = normalizeE164Phone(phone)
	if provider == "" || err != nil {
		return authprojection.AuthProviderStartResponse{}, badRequest("auth.otp_phone_required")
	}
	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		purpose = authmodel.AuthChallengePurposeLogin
	}
	now := time.Now().UTC()
	_, persistent := s.identityStore.(authrepository.AuthLoginTransactionRepository)
	otpTransactions, otpPersistent := s.identityStore.(authrepository.AuthOTPTransactionRepository)
	if persistent != otpPersistent {
		return authprojection.AuthProviderStartResponse{}, internalError("resolve durable OTP transaction capabilities", errors.New("login and OTP transaction repositories must be configured together"))
	}
	if !persistent {
		s.challengeMu.Lock()
		for _, challenge := range s.challenges {
			if challenge.WorkspaceID != workspaceID || challenge.Provider != provider || challenge.Phone != phone || tokenExpired(challenge.ExpiresAt) {
				continue
			}
			if createdAt, err := time.Parse(time.RFC3339, challenge.CreatedAt); err == nil && now.Sub(createdAt) < s.otpResendCooldown {
				s.challengeMu.Unlock()
				return authprojection.AuthProviderStartResponse{}, forbidden("auth.otp_rate_limited")
			}
		}
	}
	state, err := s.randomToken()
	if err != nil {
		if !persistent {
			s.challengeMu.Unlock()
		}
		return authprojection.AuthProviderStartResponse{}, internalError("generate OTP state", err)
	}
	code, err := s.randomDigits(6)
	if err != nil {
		if !persistent {
			s.challengeMu.Unlock()
		}
		return authprojection.AuthProviderStartResponse{}, internalError("generate OTP code", err)
	}
	expiresAt := now.Add(10 * time.Minute)
	challenge := authmodel.AuthProviderChallenge{
		WorkspaceID:           workspaceID,
		ApplicationKey:        strings.TrimSpace(applicationKey),
		Provider:              provider,
		Type:                  "otp",
		Purpose:               purpose,
		Status:                authmodel.AuthChallengeStatusPending,
		UserID:                strings.TrimSpace(userID),
		State:                 state,
		Phone:                 phone,
		Code:                  code,
		MaskedDestination:     maskPhoneDestination(phone),
		RetryAt:               now.Add(s.otpResendCooldown).Format(time.RFC3339),
		AuthenticationMethods: append([]string(nil), authenticationMethods...),
		ExpiresAt:             expiresAt.Format(time.RFC3339),
		CreatedAt:             now.Format(time.RFC3339),
	}
	if persistent {
		created, err := otpTransactions.CreateAuthOTPTransaction(ctx, challenge, s.otpDeliveryKey(workspaceID, provider, phone), now.Add(s.otpResendCooldown), now)
		if err != nil {
			return authprojection.AuthProviderStartResponse{}, err
		}
		if !created {
			return authprojection.AuthProviderStartResponse{}, forbidden("auth.otp_rate_limited")
		}
	} else {
		s.challenges[state] = challenge
		s.challengeMu.Unlock()
	}
	return authprojection.AuthProviderStartResponse{
		Provider: provider, State: state, Type: challenge.Type, Purpose: challenge.Purpose, Status: challenge.Status,
		Code: code, MaskedDestination: challenge.MaskedDestination, RetryAt: challenge.RetryAt, ExpiresAt: challenge.ExpiresAt,
	}, nil
}

func (s *AuthDomainService) UpdateOTPChallengeDelivery(ctx context.Context, workspaceID, provider, state, status, deliveryRef, deliveryError string) error {
	status = strings.TrimSpace(status)
	if status != authmodel.AuthChallengeStatusActive && status != authmodel.AuthChallengeStatusFailed {
		return badRequest("auth.otp_delivery_status_invalid")
	}
	if transactions, ok := s.identityStore.(authrepository.AuthOTPTransactionRepository); ok {
		return transactions.UpdateAuthOTPTransactionStatus(ctx, workspaceID, provider, state, status, deliveryRef, deliveryError, time.Now().UTC())
	}
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	challenge, ok := s.challenges[strings.TrimSpace(state)]
	if !ok || challenge.WorkspaceID != strings.TrimSpace(workspaceID) || challenge.Provider != normalizeProvider(provider) {
		return forbidden("auth.provider_state_invalid")
	}
	challenge.Status, challenge.DeliveryRef, challenge.DeliveryError = status, strings.TrimSpace(deliveryRef), strings.TrimSpace(deliveryError)
	if status == authmodel.AuthChallengeStatusFailed {
		delete(s.challenges, challenge.State)
	} else {
		s.challenges[challenge.State] = challenge
	}
	return nil
}

func (s *AuthDomainService) otpDeliveryKey(workspaceID, provider, phone string) string {
	digest := hmac.New(sha256.New, s.secret)
	_, _ = digest.Write([]byte(strings.TrimSpace(workspaceID)))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(normalizeProvider(provider)))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(strings.TrimSpace(phone)))
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func (s *AuthDomainService) ConsumeProviderChallenge(ctx context.Context, workspaceID, provider string, state string) (authmodel.AuthProviderChallenge, error) {
	if err := ctx.Err(); err != nil {
		return authmodel.AuthProviderChallenge{}, err
	}
	provider = normalizeProvider(provider)
	state = strings.TrimSpace(state)
	if provider == "" || state == "" {
		return authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
	}
	if transactions, ok := s.identityStore.(authrepository.AuthLoginTransactionRepository); ok {
		challenge, consumed, err := transactions.ConsumeAuthLoginTransaction(ctx, workspaceID, provider, state, time.Now().UTC())
		if err != nil {
			return authmodel.AuthProviderChallenge{}, err
		}
		if !consumed {
			return authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
		}
		if _, err := identitymodel.NewWorkspaceID(challenge.WorkspaceID); err != nil {
			return authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
		}
		return challenge, nil
	}
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	challenge, ok := s.challenges[state]
	if !ok || challenge.Provider != provider || tokenExpired(challenge.ExpiresAt) {
		delete(s.challenges, state)
		return authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
	}
	if _, err := identitymodel.NewWorkspaceID(challenge.WorkspaceID); err != nil {
		delete(s.challenges, state)
		return authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
	}
	delete(s.challenges, state)
	return challenge, nil
}

func (s *AuthDomainService) ConsumeOTPChallenge(ctx context.Context, workspaceID, provider string, state string, code string) (authmodel.AuthExternalIdentityAssertion, error) {
	assertion, _, err := s.consumeOTPChallenge(ctx, workspaceID, provider, state, code, []string{authmodel.AuthChallengePurposeLogin}, "")
	return assertion, err
}

func (s *AuthDomainService) consumeOTPChallenge(ctx context.Context, workspaceID, provider string, state string, code string, allowedPurposes []string, expectedUserID string) (authmodel.AuthExternalIdentityAssertion, authmodel.AuthProviderChallenge, error) {
	if err := ctx.Err(); err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, authmodel.AuthProviderChallenge{}, err
	}
	provider = normalizeProvider(provider)
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, authmodel.AuthProviderChallenge{}, err
	}
	workspaceID = workspace.String()
	state = strings.TrimSpace(state)
	if provider == "" || state == "" {
		return authmodel.AuthExternalIdentityAssertion{}, authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
	}
	if transactions, ok := s.identityStore.(authrepository.AuthOTPTransactionRepository); ok {
		challenge, valid, err := transactions.ConsumeAuthOTPTransaction(ctx, workspaceID, provider, state, code, allowedPurposes, expectedUserID, s.otpMaxAttempts, time.Now().UTC())
		if err != nil {
			return authmodel.AuthExternalIdentityAssertion{}, authmodel.AuthProviderChallenge{}, err
		}
		if challenge.State == "" {
			return authmodel.AuthExternalIdentityAssertion{}, authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
		}
		if !valid {
			return authmodel.AuthExternalIdentityAssertion{}, challenge, forbidden("auth.otp_code_invalid")
		}
		challenge.Status = authmodel.AuthChallengeStatusConsumed
		return otpAssertion(challenge), challenge, nil
	}
	s.challengeMu.Lock()
	challenge, ok := s.challenges[state]
	if !ok || challenge.WorkspaceID != workspaceID || challenge.Provider != provider {
		s.challengeMu.Unlock()
		return authmodel.AuthExternalIdentityAssertion{}, authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
	}
	if !otpChallengeMatchesPurposeAndUser(challenge, allowedPurposes, expectedUserID) {
		s.challengeMu.Unlock()
		return authmodel.AuthExternalIdentityAssertion{}, authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
	}
	if challenge.Status != "" && challenge.Status != authmodel.AuthChallengeStatusActive {
		s.challengeMu.Unlock()
		return authmodel.AuthExternalIdentityAssertion{}, authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
	}
	if tokenExpired(challenge.ExpiresAt) {
		delete(s.challenges, state)
		s.challengeMu.Unlock()
		return authmodel.AuthExternalIdentityAssertion{}, authmodel.AuthProviderChallenge{}, forbidden("auth.provider_state_invalid")
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(challenge.Code)), []byte(strings.TrimSpace(code))) != 1 {
		challenge.Attempts++
		if challenge.Attempts >= s.otpMaxAttempts {
			delete(s.challenges, state)
		} else {
			s.challenges[state] = challenge
		}
		s.challengeMu.Unlock()
		return authmodel.AuthExternalIdentityAssertion{}, challenge, forbidden("auth.otp_code_invalid")
	}
	delete(s.challenges, state)
	s.challengeMu.Unlock()
	challenge.Status = authmodel.AuthChallengeStatusConsumed
	return otpAssertion(challenge), challenge, nil
}

func otpChallengeMatchesPurposeAndUser(challenge authmodel.AuthProviderChallenge, allowedPurposes []string, expectedUserID string) bool {
	purposeAllowed := len(allowedPurposes) == 0
	for _, purpose := range allowedPurposes {
		if strings.TrimSpace(purpose) == strings.TrimSpace(challenge.Purpose) {
			purposeAllowed = true
			break
		}
	}
	return purposeAllowed && (strings.TrimSpace(expectedUserID) == "" || strings.TrimSpace(challenge.UserID) == strings.TrimSpace(expectedUserID))
}

func normalizeE164Phone(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "00") {
		value = "+" + value[2:]
	}
	var digits strings.Builder
	for index, char := range value {
		switch {
		case char >= '0' && char <= '9':
			digits.WriteRune(char)
		case char == '+' && index == 0:
		case char == ' ' || char == '-' || char == '(' || char == ')' || char == '.':
		default:
			return "", fmt.Errorf("phone contains unsupported characters")
		}
	}
	normalized := digits.String()
	if len(normalized) < 8 || len(normalized) > 15 || normalized[0] == '0' {
		return "", fmt.Errorf("phone is not E.164 compatible")
	}
	return "+" + normalized, nil
}

func maskPhoneDestination(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 5 {
		return "****"
	}
	return value[:2] + strings.Repeat("*", len(value)-6) + value[len(value)-4:]
}

func otpAssertion(challenge authmodel.AuthProviderChallenge) authmodel.AuthExternalIdentityAssertion {
	identityEmail := otpIdentityEmail(challenge.Phone)
	return authmodel.AuthExternalIdentityAssertion{
		Provider:    challenge.Provider,
		Subject:     challenge.Phone,
		Email:       identityEmail,
		Phone:       challenge.Phone,
		DisplayName: challenge.Phone,
		Metadata:    `{"source":"otp","phone_verified":true}`,
	}
}

func otpIdentityEmail(phone string) string {
	normalized := strings.Trim(strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return -1
		}
	}, strings.TrimSpace(phone)), "-")
	if normalized == "" {
		normalized = "verified"
	}
	return normalized + "@otp.identity.invalid"
}
