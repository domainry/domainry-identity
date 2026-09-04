package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const guestRoleKey = "customer"

// GuestSession deliberately ignores the legacy role argument. Guest authority
// is a server-owned policy and must never be selected by an anonymous caller.
func (s *AuthDomainService) GuestSession(ctx context.Context, workspaceID, _ string) (authmodel.AuthSession, error) {
	s.guestMu.Lock()
	defer s.guestMu.Unlock()

	roles, err := s.identity.ListRoles(ctx)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	var guestRole identitymodel.IdentityRole
	for _, role := range roles {
		if role.Status != identitymodel.IdentityStatusActive {
			continue
		}
		if role.Key == guestRoleKey {
			guestRole = role
			break
		}
	}
	if guestRole.ID == "" {
		return authmodel.AuthSession{}, forbidden("auth.guest_role_unavailable")
	}
	definition, published := s.identity.PublishedRoleDefinition(ctx, guestRoleKey)
	if !published || !guestAssignableRole(definition) {
		return authmodel.AuthSession{}, forbidden("auth.guest_role_unavailable")
	}
	user := identitymodel.IdentityUser{
		ID: "guest_" + guestRoleKey, Name: "Guest " + guestRoleKey,
		Email: "guest-" + guestRoleKey + "@example.com", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive,
	}
	if err := s.identity.UpsertUser(ctx, user); err != nil {
		return authmodel.AuthSession{}, err
	}
	if err := s.identity.AssignUserRole(ctx, identitymodel.IdentityUserRoleAssignment{UserID: user.ID, RoleID: guestRole.ID}); err != nil {
		return authmodel.AuthSession{}, err
	}
	return s.issueSessionForAudienceWithAuthentication(ctx, workspaceID, user, s.audience, authmodel.AuthenticationContext{Methods: []string{"guest"}, AssuranceLevel: "urn:domainry:acr:0"})
}

func guestAssignableRole(role identitymodel.RoleSchema) bool {
	assignmentMode := role.AssignmentMode
	if assignmentMode == "" {
		assignmentMode = identitymodel.IdentityRoleAssignmentManual
	}
	audience := role.Audience
	if audience == "" {
		audience = identitymodel.IdentityRoleAudienceAny
	}
	risk := role.RiskLevel
	if risk == "" {
		risk = identitymodel.IdentityRoleRiskNormal
	}
	return role.Key == guestRoleKey && assignmentMode == identitymodel.IdentityRoleAssignmentManual &&
		(audience == identitymodel.IdentityRoleAudienceAny || audience == identitymodel.IdentityRoleAudienceUser) &&
		risk == identitymodel.IdentityRoleRiskNormal
}
