package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *AuthDomainService) issueSession(ctx context.Context, workspaceID string, user identitymodel.IdentityUser) (authmodel.AuthSession, error) {
	return s.issueSessionForAudience(ctx, workspaceID, user, s.audience)
}

func (s *AuthDomainService) issueSessionForAudience(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, audience string) (authmodel.AuthSession, error) {
	return s.issueSessionForAudienceWithID(ctx, workspaceID, user, "", audience)
}

func (s *AuthDomainService) issueSessionWithID(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, sessionID string) (authmodel.AuthSession, error) {
	return s.issueSessionForAudienceWithID(ctx, workspaceID, user, sessionID, s.audience)
}

func (s *AuthDomainService) issueSessionForAudienceWithID(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, sessionID, audience string) (authmodel.AuthSession, error) {
	session, refreshRecord, err := s.prepareSessionForAudienceWithID(ctx, workspaceID, user, sessionID, audience)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if err := s.identityStore.CreateAuthRefreshToken(ctx, workspaceID, refreshRecord); err != nil {
		return authmodel.AuthSession{}, err
	}
	return session, nil
}

func (s *AuthDomainService) prepareSessionWithID(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, sessionID string) (authmodel.AuthSession, identitymodel.AuthRefreshToken, error) {
	return s.prepareSessionForAudienceWithID(ctx, workspaceID, user, sessionID, s.audience)
}

func (s *AuthDomainService) prepareSessionForAudienceWithID(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, sessionID, audience string) (authmodel.AuthSession, identitymodel.AuthRefreshToken, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, err
	}
	workspaceID = workspace.String()
	roles, err := s.identity.ActiveRolesForUser(ctx, user.ID)
	if err != nil {
		return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, err
	}
	permissions, err := s.authorization.ResolveEffectivePermissions(ctx, user.ID)
	if err != nil {
		return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, err
	}
	mustChangePassword, err := s.RequiresPasswordChange(ctx, workspaceID, user.ID)
	if err != nil {
		return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, err
	}
	now := time.Now()
	expiresAt := now.Add(s.accessTTL)
	if sessionID == "" {
		sessionID = randomToken()
	}
	principal, err := s.authorization.ResolvePrincipal(ctx, user.ID)
	if err != nil {
		return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, err
	}
	if principal.AuthorizationRevision == "" {
		principal.AuthorizationRevision = "bootstrap-" + user.ID
	}
	audience = strings.TrimSpace(audience)
	if audience == "" {
		audience = s.audience
	}
	claims := authmodel.AuthClaims{
		Issuer: s.issuer, Audience: audience, Subject: user.ID,
		TenantID: workspaceID, WorkspaceID: workspaceID, SessionID: sessionID,
		AuthorizationRevision: principal.AuthorizationRevision,
		AuthenticationTime:    now.Unix(), AuthenticationMethods: []string{"pwd"}, AssuranceLevel: "urn:domainry:acr:1",
		IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), JTI: randomToken(),
	}
	accessToken := s.signClaims(claims)
	refreshToken := randomToken()
	refreshRecord := identitymodel.AuthRefreshToken{
		ID:        "refresh_" + randomToken(),
		UserID:    user.ID,
		SessionID: sessionID,
		Audience:  audience,
		TokenHash: hashRefreshToken(refreshToken),
		ExpiresAt: now.Add(s.refreshTTL).Format(time.RFC3339),
		CreatedAt: now.Format(time.RFC3339),
	}
	return authmodel.AuthSession{
		SessionID:          sessionID,
		TenantID:           claims.TenantID,
		WorkspaceID:        claims.WorkspaceID,
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		TokenType:          "Bearer",
		ExpiresAt:          expiresAt.Format(time.RFC3339),
		User:               s.authUser(user),
		Roles:              authRoles(roles),
		DefaultRole:        defaultAuthRole(roles),
		Permissions:        permissions,
		MustChangePassword: mustChangePassword,
	}, refreshRecord, nil
}

// IssueSessionForUser signs a new session from current Identity and credential
// facts. It is used after security mutations so callers never keep using the
// pre-mutation token pair.
func (s *AuthDomainService) IssueSessionForUser(ctx context.Context, workspaceID, userID string) (authmodel.AuthSession, error) {
	return s.IssueSessionForUserAndAudience(ctx, workspaceID, userID, s.audience)
}

func (s *AuthDomainService) IssueSessionForUserAndAudience(ctx context.Context, workspaceID, userID, audience string) (authmodel.AuthSession, error) {
	user, ok, err := s.identity.UserByID(ctx, userID)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if !ok || user.Status != identitymodel.IdentityStatusActive {
		return authmodel.AuthSession{}, forbidden("auth.user_disabled")
	}
	return s.issueSessionForAudience(ctx, workspaceID, user, audience)
}
