package service

import (
	"context"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// ReconcileSystemManagedBusinessRoles projects application-owned profile facts
// into durable Identity assignments before session permissions are issued.
func (s *IdentityDomainService) ReconcileSystemManagedBusinessRoles(ctx context.Context, userID string) error {
	userID = strings.TrimSpace(userID)
	if s == nil || userID == "" || s.businessProfiles == nil {
		return nil
	}
	profiles, err := s.businessProfiles.ResolveIdentityBusinessProfiles(ctx, s.workspace, userID)
	if err != nil {
		return err
	}
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return err
	}
	for _, profile := range profiles {
		bindingKey, profileID := strings.TrimSpace(profile.BindingKey), strings.TrimSpace(profile.ProfileID)
		if bindingKey == "" || profileID == "" {
			continue
		}
		for _, role := range roles {
			definition, published := s.publishedRoleDefinition(role)
			if !published || s.identityPrivilegedAutoAssignableRole(role) || definition.AssignmentMode != identitymodel.IdentityRoleAssignmentSystemManaged ||
				definition.Audience != identitymodel.IdentityRoleAudienceBusiness ||
				strings.TrimSpace(definition.RequiredBindingKey) != bindingKey {
				continue
			}
			if err := s.assignSystemManagedRole(ctx, identitymodel.IdentityUserRoleAssignment{
				UserID: userID, RoleID: role.ID, BindingKey: bindingKey, ProfileID: profileID,
			}, true); err != nil {
				return err
			}
		}
	}
	return nil
}
