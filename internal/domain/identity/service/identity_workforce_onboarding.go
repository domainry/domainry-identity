package service

import (
	"context"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *IdentityDomainService) PrepareWorkforceOnboarding(
	ctx context.Context,
	user identitymodel.IdentityUser,
	workforceProfileID string,
	roleIDs []string,
	actor identitymodel.Principal,
	reason string,
) (identitymodel.IdentityUser, []identitymodel.IdentityUserRoleAssignment, error) {
	user, err := s.prepareUser(ctx, user)
	if err != nil {
		return identitymodel.IdentityUser{}, nil, err
	}
	if !actor.Known || strings.TrimSpace(actor.UserID) == "" {
		return identitymodel.IdentityUser{}, nil, forbidden("backend.identity.entitlement_actor_required")
	}
	workforceProfileID = strings.TrimSpace(workforceProfileID)
	if workforceProfileID == "" {
		return identitymodel.IdentityUser{}, nil, badRequest("backend.identity.workforce_profile_invalid")
	}
	prepared := make([]identitymodel.IdentityUserRoleAssignment, 0, len(roleIDs))
	definitions := make([]identitymodel.RoleSchema, 0, len(roleIDs))
	seen := map[string]bool{}
	for _, roleID := range roleIDs {
		roleID = strings.TrimSpace(roleID)
		if roleID == "" {
			return identitymodel.IdentityUser{}, nil, badRequest("backend.identity.role_required")
		}
		if seen[roleID] {
			continue
		}
		seen[roleID] = true
		role, found, loadErr := s.roleByID(ctx, roleID)
		if loadErr != nil {
			return identitymodel.IdentityUser{}, nil, loadErr
		}
		if !found {
			return identitymodel.IdentityUser{}, nil, badRequest("backend.identity.role_not_found", "role", roleID)
		}
		definition, published := s.publishedRoleDefinition(role)
		if !published {
			definition = identitymodel.RoleSchema{
				Key: role.Key, Audience: identitymodel.IdentityRoleAudienceAny,
				AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
				RiskLevel:      identitymodel.IdentityRoleRiskNormal,
			}
		}
		mode := definition.AssignmentMode
		if mode == "" {
			mode = identitymodel.IdentityRoleAssignmentManual
		}
		if mode == identitymodel.IdentityRoleAssignmentSystemManaged {
			return identitymodel.IdentityUser{}, nil, forbidden("backend.identity.system_managed_role_assignment_denied")
		}
		if mode == identitymodel.IdentityRoleAssignmentRequestOnly {
			return identitymodel.IdentityUser{}, nil, forbidden("backend.identity.role_request_required")
		}
		audience := definition.Audience
		if audience == "" {
			audience = identitymodel.IdentityRoleAudienceAny
		}
		if audience != identitymodel.IdentityRoleAudienceAny && audience != identitymodel.IdentityRoleAudienceWorkforce {
			return identitymodel.IdentityUser{}, nil, forbidden("backend.identity.workforce_role_eligibility_required")
		}
		risk := definition.RiskLevel
		if risk == "" {
			risk = identitymodel.IdentityRoleRiskNormal
		}
		if risk == identitymodel.IdentityRoleRiskPrivileged && actor.UserID == user.ID {
			return identitymodel.IdentityUser{}, nil, forbidden("backend.identity.privileged_self_grant_denied")
		}
		if risk != identitymodel.IdentityRoleRiskNormal &&
			!identityStringSliceContains(actor.Role.GrantableRoleKeys, "*") &&
			!identityStringSliceContains(actor.Role.GrantableRoleKeys, definition.Key) {
			return identitymodel.IdentityUser{}, nil, forbidden("backend.identity.role_grant_ceiling_exceeded")
		}
		prepared = append(prepared, identitymodel.IdentityUserRoleAssignment{
			UserID: user.ID, RoleID: roleID, WorkforceProfileID: workforceProfileID,
			Source: "manual", Status: "active", GrantedBy: actor.UserID, GrantReason: strings.TrimSpace(reason),
		})
		definitions = append(definitions, definition)
	}
	for left := 0; left < len(definitions); left++ {
		for right := left + 1; right < len(definitions); right++ {
			if identityStringSliceContains(definitions[left].ConflictRoleKeys, definitions[right].Key) ||
				identityStringSliceContains(definitions[right].ConflictRoleKeys, definitions[left].Key) {
				return identitymodel.IdentityUser{}, nil, forbidden("backend.identity.role_conflict")
			}
		}
	}
	return user, prepared, nil
}

func ValidateNewIdentityWorkforceProfile(profile identitymodel.IdentityWorkforceProfile) error {
	return validateIdentityWorkforceProfile(profile)
}
