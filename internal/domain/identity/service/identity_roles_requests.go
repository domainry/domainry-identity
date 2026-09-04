package service

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func (s *IdentityDomainService) ListRoles(ctx context.Context) ([]identitymodel.IdentityRole, error) {
	return s.repo.ListIdentityRoles(ctx, s.workspace)
}

func (s *IdentityDomainService) SearchRoles(ctx context.Context, query identitymodel.IdentityListQuery) (identitymodel.IdentityRolePage, error) {
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return identitymodel.IdentityRolePage{}, err
	}
	cursor := identityProjectionPagination(query)
	pageSize := cursor.PageSize()
	fields := query.SearchFields
	if len(fields) == 0 {
		fields = []string{"label", "key"}
	}
	for _, field := range fields {
		if field != "label" && field != "key" && field != "description" {
			return identitymodel.IdentityRolePage{}, badRequest("backend.identity.role_search_field_invalid", "field", field)
		}
	}
	needle := strings.ToLower(strings.TrimSpace(query.Search))
	filtered := make([]identitymodel.IdentityRole, 0, len(roles))
	for _, role := range roles {
		matches := needle == ""
		for _, field := range fields {
			var value string
			switch field {
			case "label":
				value = role.Label
			case "key":
				value = role.Key
			case "description":
				value = role.Description
			}
			if strings.Contains(strings.ToLower(value), needle) {
				matches = true
				break
			}
		}
		if matches {
			filtered = append(filtered, role)
		}
	}
	total := len(filtered)
	page, err := identityProjectionPage(cursor, filtered, func(role identitymodel.IdentityRole) string { return role.ID })
	if err != nil {
		return identitymodel.IdentityRolePage{}, err
	}
	return identitymodel.IdentityRolePage{
		Items:    page.Items,
		PageSize: pageSize,
		Total:    total,
		HasNext:  page.HasNext,
		NextID:   page.NextID,
	}, nil
}

func (s *IdentityDomainService) ActiveRolesForUser(ctx context.Context, userID string) ([]identitymodel.IdentityRole, error) {
	assignments, err := s.repo.ListIdentityUserRoleAssignments(ctx, s.workspace, userID)
	if err != nil {
		return nil, err
	}
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	activeRoleIDs := map[string]struct{}{}
	now := time.Now()
	for _, assignment := range assignments {
		if identityAssignmentActive(assignment, now) {
			activeRoleIDs[assignment.RoleID] = struct{}{}
		}
	}
	out := []identitymodel.IdentityRole{}
	for _, role := range roles {
		if _, published := s.publishedRoleDefinition(role); !published {
			continue
		}
		if _, assigned := activeRoleIDs[role.ID]; assigned {
			out = append(out, role)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *IdentityDomainService) AssignUserRole(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment) error {
	assignment, _, err := s.prepareManualRoleAssignment(ctx, assignment, false)
	if err != nil {
		return err
	}
	return s.repo.AssignIdentityUserRole(ctx, s.workspace, assignment)
}

func (s *IdentityDomainService) AssignUserRoleWithinDataScope(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter) error {
	assignment, _, err := s.prepareManualRoleAssignment(ctx, assignment, false)
	if err != nil {
		return err
	}
	repository, ok := s.repo.(identityrepository.IdentityUserRoleAssignmentDataScopeRepository)
	if !ok {
		return internalError("identity user-role assignment data-scope repository unavailable", nil)
	}
	assigned, err := repository.AssignIdentityUserRoleWithinDataScope(ctx, s.workspace, assignment, scope)
	if err != nil {
		return err
	}
	if !assigned {
		return forbidden("backend.identity.data_scope_denied")
	}
	return nil
}

func (s *IdentityDomainService) prepareManualRoleAssignment(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment, deferConflictCheck bool) (identitymodel.IdentityUserRoleAssignment, identitymodel.RoleSchema, error) {
	issues, err := s.validation.ValidateRoleAssignmentConfiguration(ctx, assignment)
	if err != nil {
		return identitymodel.IdentityUserRoleAssignment{}, identitymodel.RoleSchema{}, err
	}
	if err := s.validation.FirstConfigurationError(issues); err != nil {
		return identitymodel.IdentityUserRoleAssignment{}, identitymodel.RoleSchema{}, err
	}
	role, found, err := s.roleByID(ctx, strings.TrimSpace(assignment.RoleID))
	if err != nil {
		return identitymodel.IdentityUserRoleAssignment{}, identitymodel.RoleSchema{}, err
	}
	if !found {
		return identitymodel.IdentityUserRoleAssignment{}, identitymodel.RoleSchema{}, badRequest("backend.identity.role_not_found", "role", assignment.RoleID)
	}
	definition, published := s.publishedRoleDefinition(role)
	if !published {
		definition = identitymodel.RoleSchema{Key: valueOrDefault(role.Key, role.ID), Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, RiskLevel: identitymodel.IdentityRoleRiskNormal}
	}
	if err := s.validateRoleEligibilityWithoutConflicts(ctx, assignment, definition, false); err != nil {
		return identitymodel.IdentityUserRoleAssignment{}, identitymodel.RoleSchema{}, err
	}
	if !deferConflictCheck {
		if err := s.validateRoleConflicts(ctx, assignment.UserID, definition); err != nil {
			return identitymodel.IdentityUserRoleAssignment{}, identitymodel.RoleSchema{}, err
		}
	}
	assignment.Source = "manual"
	assignment.Status = "active"
	return assignment, definition, nil
}

func (s *IdentityDomainService) validateManualRoleEligibility(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment, role identitymodel.RoleSchema) error {
	return s.validateRoleEligibility(ctx, assignment, role, false)
}

func (s *IdentityDomainService) validateRoleEligibility(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment, role identitymodel.RoleSchema, fromApprovedRequest bool) error {
	if err := s.validateRoleEligibilityWithoutConflicts(ctx, assignment, role, fromApprovedRequest); err != nil {
		return err
	}
	return s.validateRoleConflicts(ctx, assignment.UserID, role)
}

func (s *IdentityDomainService) validateRoleEligibilityWithoutConflicts(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment, role identitymodel.RoleSchema, fromApprovedRequest bool) error {
	mode := role.AssignmentMode
	if mode == "" {
		mode = identitymodel.IdentityRoleAssignmentManual
	}
	if mode == identitymodel.IdentityRoleAssignmentSystemManaged {
		return forbidden("backend.identity.system_managed_role_assignment_denied")
	}
	if mode == identitymodel.IdentityRoleAssignmentRequestOnly && !fromApprovedRequest {
		return forbidden("backend.identity.role_request_required")
	}
	audience := role.Audience
	if audience == "" {
		audience = identitymodel.IdentityRoleAudienceAny
	}
	switch audience {
	case identitymodel.IdentityRoleAudienceBusiness:
		if strings.TrimSpace(assignment.BindingKey) != strings.TrimSpace(role.RequiredBindingKey) || strings.TrimSpace(assignment.ProfileID) == "" || s.bindingEligibility == nil {
			return forbidden("backend.identity.business_role_eligibility_required")
		}
		active, err := s.bindingEligibility.IdentityRoleBindingActive(ctx, s.workspace, assignment.BindingKey, assignment.ProfileID, assignment.UserID)
		if err != nil {
			return err
		}
		if !active {
			return forbidden("backend.identity.business_role_eligibility_required")
		}
	}
	return nil
}

func (s *IdentityDomainService) validateRoleConflicts(ctx context.Context, userID string, target identitymodel.RoleSchema) error {
	assignments, err := s.repo.ListIdentityUserRoleAssignments(ctx, s.workspace, userID)
	if err != nil {
		return err
	}
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return err
	}
	return s.validateRoleConflictsAgainstAssignments(target, assignments, roles)
}

func (s *IdentityDomainService) validateRoleConflictsAgainstAssignments(target identitymodel.RoleSchema, assignments []identitymodel.IdentityUserRoleAssignment, roles []identitymodel.IdentityRole) error {
	conflicts := map[string]bool{}
	for _, key := range target.ConflictRoleKeys {
		conflicts[strings.TrimSpace(key)] = true
	}
	byID := map[string]identitymodel.RoleSchema{}
	for _, role := range roles {
		if definition, ok := s.publishedRoleDefinition(role); ok {
			byID[role.ID] = definition
		}
	}
	now := time.Now()
	for _, assignment := range assignments {
		if !identityAssignmentActive(assignment, now) {
			continue
		}
		existing, ok := byID[assignment.RoleID]
		if !ok {
			continue
		}
		if conflicts[existing.Key] || identityStringSliceContains(existing.ConflictRoleKeys, target.Key) {
			return forbidden("backend.identity.role_conflict")
		}
	}
	return nil
}

func identityStringSliceContains(values []string, expected string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(expected) {
			return true
		}
	}
	return false
}

func (s *IdentityDomainService) AssignSystemManagedRole(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment) error {
	return s.assignSystemManagedRole(ctx, assignment, false)
}

func (s *IdentityDomainService) assignSystemManagedRole(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment, bindingAlreadyResolved bool) error {
	role, found, err := s.roleByID(ctx, strings.TrimSpace(assignment.RoleID))
	if err != nil {
		return err
	}
	if !found {
		return badRequest("backend.identity.role_not_found", "role", assignment.RoleID)
	}
	definition, published := s.publishedRoleDefinition(role)
	if !published || definition.AssignmentMode != identitymodel.IdentityRoleAssignmentSystemManaged || definition.Audience != identitymodel.IdentityRoleAudienceBusiness {
		return forbidden("backend.identity.system_managed_role_required")
	}
	if strings.TrimSpace(assignment.BindingKey) != strings.TrimSpace(definition.RequiredBindingKey) || strings.TrimSpace(assignment.ProfileID) == "" || !bindingAlreadyResolved && s.bindingEligibility == nil {
		return forbidden("backend.identity.business_role_eligibility_required")
	}
	if !bindingAlreadyResolved {
		active, err := s.bindingEligibility.IdentityRoleBindingActive(ctx, s.workspace, assignment.BindingKey, assignment.ProfileID, assignment.UserID)
		if err != nil {
			return err
		}
		if !active {
			return forbidden("backend.identity.business_role_eligibility_required")
		}
	}
	if err := s.validateRoleConflicts(ctx, assignment.UserID, definition); err != nil {
		return err
	}
	assignment.Source = "profile_binding"
	assignment.Status = "active"
	return s.repo.AssignIdentityUserRole(ctx, s.workspace, assignment)
}

func (s *IdentityDomainService) RemoveUserRole(ctx context.Context, userID string, roleID string) error {
	return s.removeUserRole(ctx, userID, roleID, "", "manual_removal")
}

func (s *IdentityDomainService) RemoveUserRoleGoverned(ctx context.Context, userID, roleID, reason string, actor identitymodel.Principal) error {
	_, found, err := s.UserByIDWithinDataScope(ctx, strings.TrimSpace(userID), actor, identitycontract.IdentityUserRoleAssignmentsRevokePermission)
	if err != nil {
		return err
	}
	if !found {
		return badRequest("backend.identity.user_not_found", "user", userID)
	}
	return s.removeUserRoleWithinDataScope(ctx, userID, roleID, actor.UserID, reason, identitycontract.IdentityPermissionDataScopeFilter(actor, identitycontract.IdentityUserRoleAssignmentsRevokePermission))
}

func (s *IdentityDomainService) removeUserRoleWithinDataScope(ctx context.Context, userID, roleID, actorID, reason string, scope identitymodel.IdentityDataScopeFilter) error {
	role, found, err := s.roleByID(ctx, strings.TrimSpace(roleID))
	if err != nil {
		return err
	}
	if found {
		if definition, ok := s.publishedRoleDefinition(role); ok && definition.AssignmentMode == identitymodel.IdentityRoleAssignmentSystemManaged {
			return forbidden("backend.identity.system_managed_role_assignment_denied")
		}
	}
	repository, ok := s.repo.(identityrepository.IdentityUserRoleAssignmentDataScopeRepository)
	if !ok {
		return internalError("identity user-role assignment data-scope repository unavailable", nil)
	}
	assignments, err := repository.ListIdentityUserRoleAssignmentsWithinDataScope(ctx, s.workspace, userID, scope)
	if err != nil {
		return err
	}
	for _, assignment := range assignments {
		if assignment.RoleID != roleID || !identityAssignmentActive(assignment, time.Now()) {
			continue
		}
		assignment.Status = "revoked"
		assignment.RevokedAt = time.Now().UTC().Format(time.RFC3339)
		assignment.RevokedBy = strings.TrimSpace(actorID)
		assignment.RevokeReason = valueOrDefault(strings.TrimSpace(reason), "manual_removal")
		updated, updateErr := repository.AssignIdentityUserRoleWithinDataScope(ctx, s.workspace, assignment, scope)
		if updateErr != nil {
			return updateErr
		}
		if !updated {
			return forbidden("backend.identity.data_scope_denied")
		}
		return nil
	}
	removed, err := repository.RemoveIdentityUserRoleWithinDataScope(ctx, s.workspace, userID, roleID, scope)
	if err != nil {
		return err
	}
	if !removed {
		return forbidden("backend.identity.data_scope_denied")
	}
	return nil
}

func (s *IdentityDomainService) removeUserRole(ctx context.Context, userID, roleID, actorID, reason string) error {
	role, found, err := s.roleByID(ctx, strings.TrimSpace(roleID))
	if err != nil {
		return err
	}
	if found {
		if definition, ok := s.publishedRoleDefinition(role); ok {
			if definition.AssignmentMode == identitymodel.IdentityRoleAssignmentSystemManaged {
				return forbidden("backend.identity.system_managed_role_assignment_denied")
			}
		}
	}
	assignments, err := s.repo.ListIdentityUserRoleAssignments(ctx, s.workspace, userID)
	if err != nil {
		return err
	}
	for _, assignment := range assignments {
		if assignment.RoleID != roleID || !identityAssignmentActive(assignment, time.Now()) {
			continue
		}
		assignment.Status = "revoked"
		assignment.RevokedAt = time.Now().UTC().Format(time.RFC3339)
		assignment.RevokedBy = strings.TrimSpace(actorID)
		assignment.RevokeReason = valueOrDefault(strings.TrimSpace(reason), "manual_removal")
		return s.repo.AssignIdentityUserRole(ctx, s.workspace, assignment)
	}
	return s.repo.RemoveIdentityUserRole(ctx, s.workspace, userID, roleID)
}

func (s *IdentityDomainService) ListUserRoleAssignments(ctx context.Context, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return s.repo.ListIdentityUserRoleAssignments(ctx, s.workspace, userID)
}

func (s *IdentityDomainService) ListUserRoleAssignmentsWithinDataScope(ctx context.Context, userID string, actor identitymodel.Principal, permissionKey string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	repository, ok := s.repo.(identityrepository.IdentityUserRoleAssignmentDataScopeReader)
	if !ok {
		return nil, internalError("identity user-role assignment data-scope repository unavailable", nil)
	}
	return repository.ListIdentityUserRoleAssignmentsWithinDataScope(ctx, s.workspace, strings.TrimSpace(userID), identitycontract.IdentityPermissionDataScopeFilter(actor, permissionKey))
}

func (s *IdentityDomainService) ListAssignableRoles(ctx context.Context, targetUserID string, actor identitymodel.Principal) ([]identitymodel.IdentityRole, error) {
	targetUserID = strings.TrimSpace(targetUserID)
	if targetUserID == "" {
		return nil, badRequest("backend.identity.user_required")
	}
	target, found, err := s.UserByIDWithinDataScope(ctx, targetUserID, actor, identitycontract.IdentityUserRoleAssignmentsAssignableRolesPermission)
	if err != nil {
		return nil, err
	}
	if !found {
		return []identitymodel.IdentityRole{}, nil
	}
	if target.Status != identitymodel.IdentityStatusActive {
		return []identitymodel.IdentityRole{}, nil
	}
	bindings, err := s.repo.ListIdentityProfileBindingsByUser(ctx, s.workspace, targetUserID)
	if err != nil {
		return nil, err
	}
	activeBindings := map[string]bool{}
	for _, binding := range bindings {
		if binding.Status == identitymodel.IdentityProfileBindingActive {
			activeBindings[strings.TrimSpace(binding.BindingKey)] = true
		}
	}
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	assignments, err := s.ListUserRoleAssignmentsWithinDataScope(ctx, targetUserID, actor, identitycontract.IdentityUserRoleAssignmentsAssignableRolesPermission)
	if err != nil {
		return nil, err
	}
	out := []identitymodel.IdentityRole{}
	for _, role := range roles {
		definition, published := s.publishedRoleDefinition(role)
		if !published || s.identityPrivilegedAutoAssignableRole(role) ||
			definition.AssignmentMode == identitymodel.IdentityRoleAssignmentSystemManaged ||
			definition.AssignmentMode == identitymodel.IdentityRoleAssignmentRequestOnly {
			continue
		}
		risk := definition.RiskLevel
		if risk == "" {
			risk = identitymodel.IdentityRoleRiskNormal
		}
		if risk != identitymodel.IdentityRoleRiskNormal &&
			!identityStringSliceContains(actor.Role.GrantableRoleKeys, "*") &&
			!identityStringSliceContains(actor.Role.GrantableRoleKeys, definition.Key) {
			continue
		}
		if risk == identitymodel.IdentityRoleRiskPrivileged && actor.UserID == targetUserID {
			continue
		}
		switch definition.Audience {
		case identitymodel.IdentityRoleAudienceUser:
		case identitymodel.IdentityRoleAudienceBusiness:
			if !activeBindings[strings.TrimSpace(definition.RequiredBindingKey)] {
				continue
			}
		case identitymodel.IdentityRoleAudienceService:
			continue
		}
		if err := s.validateRoleConflictsAgainstAssignments(definition, assignments, roles); err != nil {
			if apperror.CodeOf(err) == "backend.identity.role_conflict" {
				continue
			}
			return nil, err
		}
		out = append(out, role)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Label == out[j].Label {
			return out[i].Key < out[j].Key
		}
		return out[i].Label < out[j].Label
	})
	return out, nil
}
