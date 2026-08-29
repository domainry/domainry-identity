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
	state := randomToken()
	nonce := randomToken()
	codeVerifier := randomToken() + randomToken()
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
	state := randomToken()
	now := time.Now().UTC()
	expiresAt := now.Add(10 * time.Minute)
	challenge := authmodel.AuthProviderChallenge{
		WorkspaceID:    workspaceID,
		ApplicationKey: strings.TrimSpace(applicationKey),
		Provider:       provider,
		RedirectURL:    strings.TrimSpace(acsURL),
		State:          state,
		RequestID:      "_" + randomToken(),
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
	if err := ctx.Err(); err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	provider = normalizeProvider(provider)
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	workspaceID = workspace.String()
	phone = strings.TrimSpace(phone)
	if provider == "" || phone == "" {
		return authprojection.AuthProviderStartResponse{}, badRequest("auth.otp_phone_required")
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
	state := randomToken()
	code := randomDigits(6)
	expiresAt := now.Add(10 * time.Minute)
	challenge := authmodel.AuthProviderChallenge{
		WorkspaceID:    workspaceID,
		ApplicationKey: strings.TrimSpace(applicationKey),
		Provider:       provider,
		State:          state,
		Phone:          phone,
		Code:           code,
		ExpiresAt:      expiresAt.Format(time.RFC3339),
		CreatedAt:      now.Format(time.RFC3339),
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
		Provider:  provider,
		State:     state,
		Code:      code,
		ExpiresAt: challenge.ExpiresAt,
	}, nil
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
	assertion, _, err := s.consumeOTPChallenge(ctx, workspaceID, provider, state, code)
	return assertion, err
}

func (s *AuthDomainService) consumeOTPChallenge(ctx context.Context, workspaceID, provider string, state string, code string) (authmodel.AuthExternalIdentityAssertion, string, error) {
	if err := ctx.Err(); err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, "", err
	}
	provider = normalizeProvider(provider)
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, "", err
	}
	workspaceID = workspace.String()
	state = strings.TrimSpace(state)
	if provider == "" || state == "" {
		return authmodel.AuthExternalIdentityAssertion{}, "", forbidden("auth.provider_state_invalid")
	}
	if transactions, ok := s.identityStore.(authrepository.AuthOTPTransactionRepository); ok {
		challenge, valid, err := transactions.ConsumeAuthOTPTransaction(ctx, workspaceID, provider, state, code, s.otpMaxAttempts, time.Now().UTC())
		if err != nil {
			return authmodel.AuthExternalIdentityAssertion{}, "", err
		}
		if challenge.State == "" {
			return authmodel.AuthExternalIdentityAssertion{}, "", forbidden("auth.provider_state_invalid")
		}
		if !valid {
			return authmodel.AuthExternalIdentityAssertion{}, "", forbidden("auth.otp_code_invalid")
		}
		return otpAssertion(challenge), strings.TrimSpace(challenge.ApplicationKey), nil
	}
	s.challengeMu.Lock()
	challenge, ok := s.challenges[state]
	if !ok || challenge.WorkspaceID != workspaceID || challenge.Provider != provider {
		s.challengeMu.Unlock()
		return authmodel.AuthExternalIdentityAssertion{}, "", forbidden("auth.provider_state_invalid")
	}
	if tokenExpired(challenge.ExpiresAt) {
		delete(s.challenges, state)
		s.challengeMu.Unlock()
		return authmodel.AuthExternalIdentityAssertion{}, "", forbidden("auth.provider_state_invalid")
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(challenge.Code)), []byte(strings.TrimSpace(code))) != 1 {
		challenge.Attempts++
		if challenge.Attempts >= s.otpMaxAttempts {
			delete(s.challenges, state)
		} else {
			s.challenges[state] = challenge
		}
		s.challengeMu.Unlock()
		return authmodel.AuthExternalIdentityAssertion{}, "", forbidden("auth.otp_code_invalid")
	}
	delete(s.challenges, state)
	s.challengeMu.Unlock()
	return otpAssertion(challenge), strings.TrimSpace(challenge.ApplicationKey), nil
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
