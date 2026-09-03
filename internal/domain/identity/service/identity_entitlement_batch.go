package service

import (
	"context"
	"sort"
	"strings"
	"time"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *IdentityDomainService) PrepareIdentityEntitlementBatch(ctx context.Context, items []identitymodel.IdentityEntitlementBatchItem, actor identitymodel.Principal) ([]identitymodel.IdentityEntitlementBatchItem, []identitymodel.IdentityUserRoleAssignment, error) {
	return s.PrepareIdentityEntitlementBatchForPermission(ctx, items, actor, identitycontract.IdentityEntitlementsBatchPermission)
}

func (s *IdentityDomainService) PrepareIdentityEntitlementBatchForPermission(ctx context.Context, items []identitymodel.IdentityEntitlementBatchItem, actor identitymodel.Principal, permissionKey string) ([]identitymodel.IdentityEntitlementBatchItem, []identitymodel.IdentityUserRoleAssignment, error) {
	if !actor.Known || strings.TrimSpace(actor.UserID) == "" {
		return nil, nil, forbidden("backend.identity.entitlement_actor_required")
	}
	if len(items) == 0 {
		return nil, nil, badRequest("backend.identity.entitlement_batch_empty", "items", "")
	}
	scopedRepository, ok := s.repo.(interface {
		ListIdentityUserRoleAssignmentsWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUserRoleAssignment, error)
		GetIdentityUserWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityUser, bool, error)
	})
	if !ok {
		return nil, nil, internalError("identity entitlement data-scope repository unavailable", nil)
	}
	filter := identitycontract.IdentityPermissionDataScopeFilter(actor, permissionKey)
	current, err := scopedRepository.ListIdentityUserRoleAssignmentsWithinDataScope(ctx, s.workspace, "", filter)
	if err != nil {
		return nil, nil, err
	}
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return nil, nil, err
	}
	roleByID := make(map[string]identitymodel.IdentityRole, len(roles))
	definitionByID := make(map[string]identitymodel.RoleSchema, len(roles))
	for _, role := range roles {
		roleByID[role.ID] = role
		if definition, published := s.publishedRoleDefinition(role); published {
			definitionByID[role.ID] = definition
		} else {
			definitionByID[role.ID] = identitymodel.RoleSchema{Key: valueOrDefault(role.Key, role.ID), Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, RiskLevel: identitymodel.IdentityRoleRiskNormal}
		}
	}
	final := make(map[string]identitymodel.IdentityUserRoleAssignment, len(current)+len(items))
	for _, assignment := range current {
		final[identityEntitlementAssignmentKey(assignment.UserID, assignment.RoleID)] = assignment
	}
	normalized := make([]identitymodel.IdentityEntitlementBatchItem, 0, len(items))
	prepared := make([]identitymodel.IdentityUserRoleAssignment, 0, len(items))
	seen := map[string]bool{}
	users := map[string]identitymodel.IdentityUser{}
	now := time.Now().UTC()
	for _, raw := range items {
		item := normalizeIdentityEntitlementBatchItem(raw)
		key := identityEntitlementAssignmentKey(item.UserID, item.RoleID)
		if item.UserID == "" || item.RoleID == "" || seen[key] {
			return nil, nil, badRequest("backend.identity.entitlement_batch_item_invalid", "role", item.RoleID)
		}
		seen[key] = true
		target, loaded := users[item.UserID]
		if !loaded {
			var found bool
			target, found, err = scopedRepository.GetIdentityUserWithinDataScope(ctx, s.workspace, item.UserID, filter)
			if err != nil {
				return nil, nil, err
			}
			if !found {
				return nil, nil, badRequest("backend.identity.user_not_found", "user", item.UserID)
			}
			users[item.UserID] = target
		}
		role, found := roleByID[item.RoleID]
		if !found {
			return nil, nil, badRequest("backend.identity.role_not_found", "role", item.RoleID)
		}
		definition := definitionByID[item.RoleID]
		var assignment identitymodel.IdentityUserRoleAssignment
		switch item.Operation {
		case identitymodel.IdentityEntitlementOperationGrant:
			assignment = identitymodel.IdentityUserRoleAssignment{
				UserID: item.UserID, RoleID: item.RoleID,
				BindingKey: item.BindingKey, ProfileID: item.ProfileID, ValidFrom: item.ValidFrom, ValidUntil: item.ValidUntil,
				GrantedBy: actor.UserID, GrantReason: item.Reason,
			}
			assignment, definition, err = s.prepareManualRoleAssignment(ctx, assignment, true)
			if err != nil {
				return nil, nil, err
			}
			if err := validateIdentityEntitlementGrantCeiling(actor, assignment, definition); err != nil {
				return nil, nil, err
			}
		case identitymodel.IdentityEntitlementOperationRevoke:
			if definition.AssignmentMode == identitymodel.IdentityRoleAssignmentSystemManaged {
				return nil, nil, forbidden("backend.identity.system_managed_role_assignment_denied")
			}
			existing, active := final[key]
			if !active || !identityAssignmentActive(existing, now) {
				return nil, nil, badRequest("backend.identity.entitlement_not_active", "role", role.ID)
			}
			assignment = existing
			assignment.Status = "revoked"
			assignment.RevokedBy = actor.UserID
			assignment.RevokedAt = now.Format(time.RFC3339)
			assignment.RevokeReason = item.Reason
		default:
			return nil, nil, badRequest("backend.identity.entitlement_batch_operation_invalid", "operation", item.Operation)
		}
		final[key] = assignment
		normalized = append(normalized, item)
		prepared = append(prepared, assignment)
	}
	if err := validateIdentityEntitlementFinalState(final, definitionByID, now); err != nil {
		return nil, nil, err
	}
	return normalized, prepared, nil
}

func normalizeIdentityEntitlementBatchItem(item identitymodel.IdentityEntitlementBatchItem) identitymodel.IdentityEntitlementBatchItem {
	item.Operation = strings.TrimSpace(item.Operation)
	item.UserID = strings.TrimSpace(item.UserID)
	item.RoleID = strings.TrimSpace(item.RoleID)
	item.BindingKey = strings.TrimSpace(item.BindingKey)
	item.ProfileID = strings.TrimSpace(item.ProfileID)
	item.ValidFrom = strings.TrimSpace(item.ValidFrom)
	item.ValidUntil = strings.TrimSpace(item.ValidUntil)
	item.Reason = strings.TrimSpace(item.Reason)
	return item
}

func identityEntitlementAssignmentKey(userID, roleID string) string {
	return strings.TrimSpace(userID) + "\x00" + strings.TrimSpace(roleID)
}

func validateIdentityEntitlementGrantCeiling(actor identitymodel.Principal, assignment identitymodel.IdentityUserRoleAssignment, definition identitymodel.RoleSchema) error {
	risk := definition.RiskLevel
	if risk == "" {
		risk = identitymodel.IdentityRoleRiskNormal
	}
	if risk == identitymodel.IdentityRoleRiskPrivileged && strings.TrimSpace(actor.UserID) == strings.TrimSpace(assignment.UserID) {
		return forbidden("backend.identity.privileged_self_grant_denied")
	}
	if risk != identitymodel.IdentityRoleRiskNormal &&
		!identityStringSliceContains(actor.Role.GrantableRoleKeys, "*") &&
		!identityStringSliceContains(actor.Role.GrantableRoleKeys, definition.Key) {
		return forbidden("backend.identity.role_grant_ceiling_exceeded")
	}
	return nil
}

func validateIdentityEntitlementFinalState(final map[string]identitymodel.IdentityUserRoleAssignment, definitions map[string]identitymodel.RoleSchema, now time.Time) error {
	activeByUser := map[string][]identitymodel.RoleSchema{}
	for _, assignment := range final {
		if !identityAssignmentActive(assignment, now) {
			continue
		}
		if definition, found := definitions[assignment.RoleID]; found {
			activeByUser[assignment.UserID] = append(activeByUser[assignment.UserID], definition)
		}
	}
	for _, roles := range activeByUser {
		sort.Slice(roles, func(i, j int) bool { return roles[i].Key < roles[j].Key })
		for left := 0; left < len(roles); left++ {
			for right := left + 1; right < len(roles); right++ {
				if identityStringSliceContains(roles[left].ConflictRoleKeys, roles[right].Key) ||
					identityStringSliceContains(roles[right].ConflictRoleKeys, roles[left].Key) {
					return forbidden("backend.identity.role_conflict")
				}
			}
		}
	}
	return nil
}
