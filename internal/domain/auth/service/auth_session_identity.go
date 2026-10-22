package service

import authprojection "github.com/domainry/domainry-identity/internal/domain/auth/projection"

import (
	"context"
	"slices"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypolicy "github.com/domainry/domainry-identity/internal/domain/identity/policy"
)

func (s *AuthDomainService) Me(ctx context.Context, accessToken string) (authprojection.AuthMeResponse, error) {
	claims, err := s.VerifyAccessToken(ctx, accessToken)
	if err != nil {
		return authprojection.AuthMeResponse{}, err
	}
	user, ok, err := s.identity.UserByID(ctx, claims.Subject)
	if err != nil {
		return authprojection.AuthMeResponse{}, err
	}
	if !ok || user.Status != identitymodel.IdentityStatusActive {
		return authprojection.AuthMeResponse{}, forbidden("auth.user_disabled")
	}
	roles, err := s.identity.ActiveRolesForUser(ctx, user.UserID)
	if err != nil {
		return authprojection.AuthMeResponse{}, err
	}
	principal, err := s.authorization.ResolvePrincipal(ctx, user.UserID)
	if err != nil {
		return authprojection.AuthMeResponse{}, err
	}
	if !principal.Known || principal.AuthorizationRevision == "" {
		return authprojection.AuthMeResponse{}, forbidden("auth.user_disabled")
	}
	// Permissions, their bearer revision, and the independently changing scope
	// revision must come from the same current principal.
	permissions := identitymodel.RolePermissionKeys(principal.Role.Permissions)
	slices.Sort(permissions)
	permissions = slices.Compact(permissions)
	mustChangePassword, err := s.RequiresPasswordChange(ctx, claims.WorkspaceID, user.UserID)
	if err != nil {
		return authprojection.AuthMeResponse{}, err
	}
	return authprojection.AuthMeResponse{
		User:                  s.authUser(user),
		Roles:                 authRoles(roles),
		DefaultRole:           identitypolicy.SelectDefaultRole(roles),
		Permissions:           permissions,
		AuthorizationRevision: principal.AuthorizationRevision,
		ScopeRevision:         principal.ScopeRevision,
		MustChangePassword:    mustChangePassword,
	}, nil
}

func (s *AuthDomainService) PrincipalFromBearer(ctx context.Context, authorization string, requestID string) (identitymodel.Principal, error) {
	token := bearerToken(authorization)
	if token == "" {
		return identitymodel.Principal{}, forbidden("auth.token_required")
	}
	claims, err := s.VerifyAccessToken(ctx, token)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	workspace, err := identitymodel.NewWorkspaceID(claims.WorkspaceID)
	if err != nil {
		return identitymodel.Principal{}, forbidden("auth.workspace_scope_required")
	}
	workspaceID := workspace.String()
	ctx = requestcontext.WithWorkspaceID(ctx, workspaceID)
	principal, err := s.authorization.ResolvePrincipal(ctx, claims.Subject)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	principal.WorkspaceID = workspaceID
	principal.RequestID = requestID
	return principal, nil
}
