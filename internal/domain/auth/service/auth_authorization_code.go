package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *AuthDomainService) IssueAuthorizationCode(ctx context.Context, applicationKey, redirectURL string, session authmodel.AuthSession) (string, error) {
	return s.issueAuthorizationCode(ctx, applicationKey, redirectURL, session, "", "", true)
}

func (s *AuthDomainService) IssueBrowserAuthorizationCode(ctx context.Context, workspaceID, refreshToken, sourceApplicationKey, targetApplicationKey, redirectURL, codeChallenge, codeChallengeMethod string) (string, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	refreshToken = strings.TrimSpace(refreshToken)
	sourceApplicationKey = strings.TrimSpace(sourceApplicationKey)
	targetApplicationKey = strings.TrimSpace(targetApplicationKey)
	if workspaceID == "" || refreshToken == "" || sourceApplicationKey == "" || targetApplicationKey == "" || !validPKCEChallenge(codeChallenge, codeChallengeMethod) {
		return "", badRequest("auth.authorization_code_request_invalid")
	}
	current, found, err := s.identityStore.GetAuthRefreshTokenByHash(ctx, workspaceID, hashRefreshToken(refreshToken))
	if err != nil {
		return "", err
	}
	if !found || tokenExpired(current.ExpiresAt) || strings.TrimSpace(current.RevokedAt) != "" {
		return "", forbidden("auth.session_expired")
	}
	if strings.TrimSpace(current.Audience) != sourceApplicationKey {
		return "", forbidden("identity.application_mismatch")
	}
	user, found, err := s.identity.UserByID(ctx, current.UserID)
	if err != nil {
		return "", err
	}
	if !found || user.Status != identitymodel.IdentityStatusActive {
		return "", forbidden("auth.user_disabled")
	}
	targetSession, err := s.issueSessionForAudienceWithIDAndAuthentication(ctx, workspaceID, user, "", targetApplicationKey, authmodel.AuthenticationContext{
		AuthenticationTime: current.AuthenticationTime,
		Methods:            current.AuthenticationMethods,
		AssuranceLevel:     current.AssuranceLevel,
	})
	if err != nil {
		return "", err
	}
	code, err := s.issueAuthorizationCode(ctx, targetApplicationKey, redirectURL, targetSession, codeChallenge, codeChallengeMethod, false)
	if err != nil {
		_ = s.LogoutForApplication(ctx, workspaceID, targetSession.RefreshToken, targetApplicationKey)
		return "", err
	}
	return code, nil
}

func (s *AuthDomainService) issueAuthorizationCode(ctx context.Context, applicationKey, redirectURL string, session authmodel.AuthSession, codeChallenge, codeChallengeMethod string, validateRegisteredRedirect bool) (string, error) {
	repository, ok := s.identityStore.(authrepository.AuthAuthorizationCodeRepository)
	if !ok {
		return "", internalError("authorization code store unavailable", nil)
	}
	applicationKey, redirectURL = strings.TrimSpace(applicationKey), strings.TrimSpace(redirectURL)
	if applicationKey == "" || !validAuthorizationRedirectURL(redirectURL) || strings.TrimSpace(session.WorkspaceID) == "" || !validOptionalPKCEChallenge(codeChallenge, codeChallengeMethod) {
		return "", badRequest("auth.authorization_code_request_invalid")
	}
	if validateRegisteredRedirect {
		applications, ok := s.identityStore.(authrepository.AuthApplicationRepository)
		if !ok {
			return "", internalError("authorization application store unavailable", nil)
		}
		registered, err := applications.AuthorizationRedirectRegistered(ctx, session.WorkspaceID, applicationKey, redirectURL)
		if err != nil {
			return "", err
		}
		if !registered {
			return "", forbidden("identity.redirect_url_not_registered")
		}
	}
	now := time.Now().UTC()
	first, err := s.randomToken()
	if err != nil {
		return "", internalError("generate authorization code", err)
	}
	second, err := s.randomToken()
	if err != nil {
		return "", internalError("generate authorization code", err)
	}
	code := first + second
	err = repository.CreateAuthAuthorizationCode(ctx, authmodel.AuthAuthorizationCode{
		Code: code, WorkspaceID: session.WorkspaceID, ApplicationKey: applicationKey, Session: session, RedirectURL: redirectURL,
		CodeChallenge: strings.TrimSpace(codeChallenge), CodeChallengeMethod: strings.TrimSpace(codeChallengeMethod),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), CreatedAt: now.Format(time.RFC3339Nano),
	})
	return code, err
}

func (s *AuthDomainService) ExchangeAuthorizationCode(ctx context.Context, code, applicationKey, redirectURL, codeVerifier string) (authmodel.AuthSession, error) {
	repository, ok := s.identityStore.(authrepository.AuthAuthorizationCodeRepository)
	if !ok {
		return authmodel.AuthSession{}, internalError("authorization code store unavailable", nil)
	}
	if strings.TrimSpace(code) == "" || strings.TrimSpace(applicationKey) == "" || !validAuthorizationRedirectURL(redirectURL) {
		return authmodel.AuthSession{}, badRequest("auth.authorization_code_request_invalid")
	}
	resolver, ok := s.identityStore.(authrepository.AuthAuthorizationCodeWorkspaceRepository)
	if !ok {
		return authmodel.AuthSession{}, internalError("authorization code workspace resolver unavailable", nil)
	}
	now := time.Now().UTC()
	workspaceID, found, err := resolver.AuthorizationCodeWorkspace(ctx, code, applicationKey, redirectURL, now)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if !found {
		return authmodel.AuthSession{}, forbidden("auth.authorization_code_invalid")
	}
	session, consumed, err := repository.ConsumeAuthAuthorizationCode(ctx, workspaceID, code, applicationKey, redirectURL, strings.TrimSpace(codeVerifier), now)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if !consumed || strings.TrimSpace(session.WorkspaceID) != workspaceID {
		return authmodel.AuthSession{}, forbidden("auth.authorization_code_invalid")
	}
	return session, nil
}

func validPKCEChallenge(challenge, method string) bool {
	challenge = strings.TrimSpace(challenge)
	return method == "S256" && len(challenge) == 43 && validPKCEValue(challenge)
}

func validOptionalPKCEChallenge(challenge, method string) bool {
	challenge, method = strings.TrimSpace(challenge), strings.TrimSpace(method)
	return challenge == "" && method == "" || validPKCEChallenge(challenge, method)
}

func validPKCEVerifier(verifier string) bool {
	verifier = strings.TrimSpace(verifier)
	return len(verifier) >= 43 && len(verifier) <= 128 && validPKCEValue(verifier)
}

func validPKCEValue(value string) bool {
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-._~", character) {
			continue
		}
		return false
	}
	return value != ""
}

func pkceS256(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func validAuthorizationRedirectURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && parsed.IsAbs() && parsed.User == nil && parsed.Fragment == "" && (parsed.Scheme == "https" || parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"))
}
