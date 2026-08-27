package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *AuthDomainService) GuestSession(ctx context.Context, workspaceID, roleKey string) (authmodel.AuthSession, error) {
	s.guestMu.Lock()
	defer s.guestMu.Unlock()

	roleKey = strings.TrimSpace(roleKey)
	if roleKey == "" {
		roleKey = "customer"
	}
	roles, err := s.identity.ListRoles(ctx)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	var guestRole identitymodel.IdentityRole
	for _, role := range roles {
		if role.Status != identitymodel.IdentityStatusActive {
			continue
		}
		if role.Key == roleKey || role.ID == roleKey {
			guestRole = role
			break
		}
	}
	if guestRole.ID == "" {
		return authmodel.AuthSession{}, forbidden("auth.guest_role_unavailable")
	}
	user := identitymodel.IdentityUser{
		ID: "guest_" + roleKey, Name: "Guest " + roleKey,
		Email: "guest-" + roleKey + "@example.com", Status: identitymodel.IdentityStatusActive,
	}
	if err := s.identity.UpsertUser(ctx, user); err != nil {
		return authmodel.AuthSession{}, err
	}
	if err := s.identity.AssignUserRole(ctx, identitymodel.IdentityUserRoleAssignment{UserID: user.ID, RoleID: guestRole.ID}); err != nil {
		return authmodel.AuthSession{}, err
	}
	return s.issueSession(ctx, workspaceID, user)
}
