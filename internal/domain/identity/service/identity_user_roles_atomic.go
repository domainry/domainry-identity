package service

import (
	"context"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func (s *IdentityDomainService) UpsertUserWithRoles(
	ctx context.Context,
	user identitymodel.IdentityUser,
	assignments []identitymodel.IdentityUserRoleAssignment,
	actor identitymodel.Principal,
) error {
	user, err := s.prepareUser(ctx, user)
	if err != nil {
		return err
	}
	if !actor.Known || strings.TrimSpace(actor.UserID) == "" {
		return forbidden("backend.identity.entitlement_actor_required")
	}
	if !identityActorCanManageRoleTarget(actor, user) {
		return forbidden("backend.identity.role_target_scope_denied")
	}
	prepared := make([]identitymodel.IdentityUserRoleAssignment, 0, len(assignments))
	definitions := make([]identitymodel.RoleSchema, 0, len(assignments))
	seen := map[string]bool{}
	for _, assignment := range assignments {
		assignment.UserID = user.ID
		assignment.RoleID = strings.TrimSpace(assignment.RoleID)
		if assignment.RoleID == "" || seen[assignment.RoleID] {
			if assignment.RoleID == "" {
				return badRequest("backend.identity.role_required")
			}
			continue
		}
		seen[assignment.RoleID] = true
		issues, validateErr := s.validation.ValidateRoleAssignmentConfiguration(ctx, assignment)
		if validateErr != nil {
			return validateErr
		}
		filtered := issues[:0]
		for _, issue := range issues {
			if issue.ErrorCode != "backend.identity.user_not_found" {
				filtered = append(filtered, issue)
			}
		}
		if validateErr = s.validation.FirstConfigurationError(filtered); validateErr != nil {
			return validateErr
		}
		role, found, loadErr := s.roleByID(ctx, assignment.RoleID)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return badRequest("backend.identity.role_not_found", "role", assignment.RoleID)
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
			return err
		}
		risk := definition.RiskLevel
		if risk == "" {
			risk = identitymodel.IdentityRoleRiskNormal
		}
		if risk == identitymodel.IdentityRoleRiskPrivileged && actor.UserID == user.ID {
			return forbidden("backend.identity.privileged_self_grant_denied")
		}
		if risk != identitymodel.IdentityRoleRiskNormal &&
			!identityStringSliceContains(actor.Role.GrantableRoleKeys, "*") &&
			!identityStringSliceContains(actor.Role.GrantableRoleKeys, definition.Key) {
			return forbidden("backend.identity.role_grant_ceiling_exceeded")
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
				return forbidden("backend.identity.role_conflict")
			}
		}
	}
	repository, ok := s.repo.(identityrepository.IdentityUserRoleReconcileRepository)
	if !ok {
		return internalError("atomic identity user role reconcile unavailable", nil)
	}
	return repository.UpsertIdentityUserWithRoleAssignmentsAtomically(ctx, s.workspace, user, prepared)
}
