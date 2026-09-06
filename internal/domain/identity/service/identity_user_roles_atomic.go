package service

import (
	"context"
	"strings"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func (s *IdentityDomainService) UpsertUserWithRoles(
	ctx context.Context,
	user identitymodel.IdentityUser,
	assignments []identitymodel.IdentityUserRoleAssignment,
	actor identitymodel.Principal,
) error {
	user, prepared, err := s.PrepareUserWithExactRoles(ctx, user, assignments, actor)
	if err != nil {
		return err
	}
	// The request body is mutation intent, not authorization evidence. Resolve
	// the target through persisted user facts; this endpoint fails closed for a
	// new ID instead of trusting a client-supplied organization.
	if _, found, loadErr := s.UserByIDWithinDataScope(ctx, user.ID, actor, identitycontract.IdentityUserRoleAssignmentsAccountUpdatePermission); loadErr != nil {
		return loadErr
	} else if !found {
		return forbidden("backend.identity.data_scope_denied")
	}
	repository, ok := s.repo.(identityrepository.IdentityUserRoleDataScopeReconcileRepository)
	if !ok {
		return internalError("scoped atomic identity user role reconcile unavailable", nil)
	}
	updated, err := repository.UpsertIdentityUserWithRoleAssignmentsWithinDataScopeAtomically(ctx, s.workspace, user, prepared, identitycontract.IdentityPermissionDataScopeFilter(actor, identitycontract.IdentityUserRoleAssignmentsAccountUpdatePermission))
	if err != nil {
		return err
	}
	if !updated {
		return forbidden("backend.identity.data_scope_denied")
	}
	return nil
}

// PrepareUserWithExactRoles validates and canonicalizes a complete desired
// manual-role set without persisting it. Application-owned multi-aggregate
// transactions use this exact same role hierarchy and eligibility policy as
// the ordinary account-and-roles endpoint.
func (s *IdentityDomainService) PrepareUserWithExactRoles(
	ctx context.Context,
	user identitymodel.IdentityUser,
	assignments []identitymodel.IdentityUserRoleAssignment,
	actor identitymodel.Principal,
) (identitymodel.IdentityUser, []identitymodel.IdentityUserRoleAssignment, error) {
	user, err := s.prepareUser(ctx, user)
	if err != nil {
		return identitymodel.IdentityUser{}, nil, err
	}
	if !actor.Known || strings.TrimSpace(actor.UserID) == "" {
		return identitymodel.IdentityUser{}, nil, forbidden("backend.identity.entitlement_actor_required")
	}
	prepared := make([]identitymodel.IdentityUserRoleAssignment, 0, len(assignments))
	definitions := make([]identitymodel.RoleSchema, 0, len(assignments))
	seen := map[string]bool{}
	for _, assignment := range assignments {
		assignment.UserID = user.ID
		assignment.RoleID = strings.TrimSpace(assignment.RoleID)
		if assignment.RoleID == "" || seen[assignment.RoleID] {
			if assignment.RoleID == "" {
				return identitymodel.IdentityUser{}, nil, badRequest("backend.identity.role_required")
			}
			continue
		}
		seen[assignment.RoleID] = true
		issues, validateErr := s.validation.ValidateRoleAssignmentConfiguration(ctx, assignment)
		if validateErr != nil {
			return identitymodel.IdentityUser{}, nil, validateErr
		}
		filtered := issues[:0]
		for _, issue := range issues {
			if issue.ErrorCode != "backend.identity.user_not_found" {
				filtered = append(filtered, issue)
			}
		}
		if validateErr = s.validation.FirstConfigurationError(filtered); validateErr != nil {
			return identitymodel.IdentityUser{}, nil, validateErr
		}
		role, found, loadErr := s.roleByID(ctx, assignment.RoleID)
		if loadErr != nil {
			return identitymodel.IdentityUser{}, nil, loadErr
		}
		if !found {
			return identitymodel.IdentityUser{}, nil, badRequest("backend.identity.role_not_found", "role", assignment.RoleID)
		}
		definition, published := s.publishedRoleDefinition(role)
		if !published {
			definition = identitymodel.RoleSchema{
				Key: role.Key, Audience: identitymodel.IdentityRoleAudienceAny,
				AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
				RiskLevel:      identitymodel.IdentityRoleRiskNormal,
			}
		}
		if err := s.validateRoleEligibilityWithoutConflicts(ctx, assignment, definition, false); err != nil {
			return identitymodel.IdentityUser{}, nil, err
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
		assignment.Source = "manual"
		assignment.Status = "active"
		assignment.GrantedBy = actor.UserID
		prepared = append(prepared, assignment)
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
