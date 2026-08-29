package service

import (
	"context"
	"net/url"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
)

func (s *AuthDomainService) IssueAuthorizationCode(ctx context.Context, applicationKey, redirectURL string, session authmodel.AuthSession) (string, error) {
	repository, ok := s.identityStore.(authrepository.AuthAuthorizationCodeRepository)
	if !ok {
		return "", internalError("authorization code store unavailable", nil)
	}
	applicationKey, redirectURL = strings.TrimSpace(applicationKey), strings.TrimSpace(redirectURL)
	if applicationKey == "" || !validAuthorizationRedirectURL(redirectURL) || strings.TrimSpace(session.WorkspaceID) == "" {
		return "", badRequest("auth.authorization_code_request_invalid")
	}
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
	now := time.Now().UTC()
	code := randomToken() + randomToken()
	err = repository.CreateAuthAuthorizationCode(ctx, authmodel.AuthAuthorizationCode{Code: code, WorkspaceID: session.WorkspaceID, ApplicationKey: applicationKey, Session: session, RedirectURL: redirectURL, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), CreatedAt: now.Format(time.RFC3339Nano)})
	return code, err
}

func (s *AuthDomainService) ExchangeAuthorizationCode(ctx context.Context, workspaceID, code, applicationKey, redirectURL string) (authmodel.AuthSession, error) {
	repository, ok := s.identityStore.(authrepository.AuthAuthorizationCodeRepository)
	if !ok {
		return authmodel.AuthSession{}, internalError("authorization code store unavailable", nil)
	}
	if strings.TrimSpace(workspaceID) == "" || strings.TrimSpace(code) == "" || strings.TrimSpace(applicationKey) == "" || !validAuthorizationRedirectURL(redirectURL) {
		return authmodel.AuthSession{}, badRequest("auth.authorization_code_request_invalid")
	}
	session, consumed, err := repository.ConsumeAuthAuthorizationCode(ctx, workspaceID, code, applicationKey, redirectURL, time.Now().UTC())
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if !consumed {
		return authmodel.AuthSession{}, forbidden("auth.authorization_code_invalid")
	}
	return session, nil
}

func validAuthorizationRedirectURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && parsed.IsAbs() && parsed.User == nil && parsed.Fragment == "" && (parsed.Scheme == "https" || parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"))
}
