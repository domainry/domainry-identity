package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"sort"
	"strings"
	"time"

	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *AuthDomainService) issueSession(ctx context.Context, workspaceID string, user identitymodel.IdentityUser) (authmodel.AuthSession, error) {
	return s.issueSessionForAudienceWithAuthentication(ctx, workspaceID, user, s.audience, passwordAuthenticationContext())
}

func (s *AuthDomainService) issueSessionForAudience(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, audience string) (authmodel.AuthSession, error) {
	return s.issueSessionForAudienceWithAuthentication(ctx, workspaceID, user, audience, passwordAuthenticationContext())
}

func (s *AuthDomainService) issueSessionForAudienceWithAuthentication(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, audience string, authentication authmodel.AuthenticationContext) (authmodel.AuthSession, error) {
	return s.issueSessionForAudienceWithIDAndAuthentication(ctx, workspaceID, user, "", audience, authentication)
}

func (s *AuthDomainService) issueSessionWithID(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, sessionID string) (authmodel.AuthSession, error) {
	return s.issueSessionForAudienceWithIDAndAuthentication(ctx, workspaceID, user, sessionID, s.audience, passwordAuthenticationContext())
}

func (s *AuthDomainService) issueSessionForAudienceWithID(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, sessionID, audience string) (authmodel.AuthSession, error) {
	return s.issueSessionForAudienceWithIDAndAuthentication(ctx, workspaceID, user, sessionID, audience, passwordAuthenticationContext())
}

func (s *AuthDomainService) issueSessionForAudienceWithIDAndAuthentication(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, sessionID, audience string, authentication authmodel.AuthenticationContext) (authmodel.AuthSession, error) {
	session, refreshRecord, err := s.prepareSessionForAudienceWithIDAndAuthentication(ctx, workspaceID, user, sessionID, audience, authentication)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if err := s.identityStore.CreateAuthRefreshToken(ctx, workspaceID, refreshRecord); err != nil {
		return authmodel.AuthSession{}, err
	}
	return session, nil
}

func (s *AuthDomainService) prepareSessionWithID(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, sessionID string) (authmodel.AuthSession, identitymodel.AuthRefreshToken, error) {
	return s.prepareSessionForAudienceWithIDAndAuthentication(ctx, workspaceID, user, sessionID, s.audience, passwordAuthenticationContext())
}

func (s *AuthDomainService) prepareSessionForAudienceWithID(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, sessionID, audience string) (authmodel.AuthSession, identitymodel.AuthRefreshToken, error) {
	return s.prepareSessionForAudienceWithIDAndAuthentication(ctx, workspaceID, user, sessionID, audience, passwordAuthenticationContext())
}

func (s *AuthDomainService) prepareSessionForAudienceWithIDAndAuthentication(ctx context.Context, workspaceID string, user identitymodel.IdentityUser, sessionID, audience string, authentication authmodel.AuthenticationContext) (authmodel.AuthSession, identitymodel.AuthRefreshToken, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, err
	}
	workspaceID = workspace.String()
	if reconciler, ok := s.identity.(authcontract.AuthSystemManagedRoleReconciler); ok {
		if err := reconciler.ReconcileSystemManagedBusinessRoles(ctx, user.ID); err != nil {
			return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, err
		}
	}
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
	authentication = normalizeAuthenticationContext(authentication, now)
	expiresAt := now.Add(s.accessTTL)
	if sessionID == "" {
		sessionID, err = s.randomToken()
		if err != nil {
			return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, internalError("generate session identifier", err)
		}
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
	jti, err := s.randomToken()
	if err != nil {
		return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, internalError("generate access token identifier", err)
	}
	claims := authmodel.AuthClaims{
		Issuer: s.issuer, Audience: audience, Subject: user.ID,
		TenantID: workspaceID, WorkspaceID: workspaceID, SessionID: sessionID,
		AuthorizationRevision: principal.AuthorizationRevision,
		AuthenticationTime:    authentication.AuthenticationTime, AuthenticationMethods: authentication.Methods, AssuranceLevel: authentication.AssuranceLevel,
		IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), JTI: jti,
	}
	accessToken, err := s.signClaims(claims)
	if err != nil {
		return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, err
	}
	refreshToken, err := s.randomToken()
	if err != nil {
		return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, internalError("generate refresh token", err)
	}
	refreshID, err := s.randomToken()
	if err != nil {
		return authmodel.AuthSession{}, identitymodel.AuthRefreshToken{}, internalError("generate refresh token identifier", err)
	}
	refreshRecord := identitymodel.AuthRefreshToken{
		ID:                    "refresh_" + refreshID,
		UserID:                user.ID,
		SessionID:             sessionID,
		Audience:              audience,
		AuthenticationTime:    authentication.AuthenticationTime,
		AuthenticationMethods: append([]string(nil), authentication.Methods...),
		AssuranceLevel:        authentication.AssuranceLevel,
		TokenHash:             hashRefreshToken(refreshToken),
		ExpiresAt:             now.Add(s.refreshTTL).Format(time.RFC3339),
		CreatedAt:             now.Format(time.RFC3339),
	}
	return authmodel.AuthSession{
		SessionID:             sessionID,
		TenantID:              claims.TenantID,
		WorkspaceID:           claims.WorkspaceID,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		TokenType:             "Bearer",
		ExpiresAt:             expiresAt.Format(time.RFC3339),
		User:                  s.authUser(user),
		Roles:                 authRoles(roles),
		DefaultRole:           defaultAuthRole(roles),
		Permissions:           permissions,
		MustChangePassword:    mustChangePassword,
		AuthenticationTime:    claims.AuthenticationTime,
		AuthenticationMethods: append([]string(nil), claims.AuthenticationMethods...),
		AssuranceLevel:        claims.AssuranceLevel,
	}, refreshRecord, nil
}

func passwordAuthenticationContext() authmodel.AuthenticationContext {
	return authmodel.AuthenticationContext{Methods: []string{"pwd"}, AssuranceLevel: "urn:domainry:acr:1"}
}

func normalizeAuthenticationContext(value authmodel.AuthenticationContext, now time.Time) authmodel.AuthenticationContext {
	seen := map[string]bool{}
	methods := make([]string, 0, len(value.Methods))
	for _, method := range value.Methods {
		method = strings.ToLower(strings.TrimSpace(method))
		if method == "" || seen[method] {
			continue
		}
		seen[method] = true
		methods = append(methods, method)
	}
	if len(methods) == 0 {
		methods = []string{"pwd"}
	}
	sort.Strings(methods)
	value.Methods = methods
	if value.AuthenticationTime <= 0 {
		value.AuthenticationTime = now.Unix()
	}
	if strings.TrimSpace(value.AssuranceLevel) == "" {
		switch {
		case len(methods) > 1:
			value.AssuranceLevel = "urn:domainry:acr:2"
		case methods[0] == "guest":
			value.AssuranceLevel = "urn:domainry:acr:0"
		default:
			value.AssuranceLevel = "urn:domainry:acr:1"
		}
	}
	return value
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
