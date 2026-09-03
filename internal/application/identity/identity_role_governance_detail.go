package identity

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// RoleGovernanceDetail composes the published role and its governed references
// into one query projection. Mutations use versioned metadata publication.
func (s *IdentityApplicationService) RoleGovernanceDetail(ctx context.Context, roleID string) (identitymodel.IdentityRoleGovernanceDetail, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityRoleGovernanceDetail{}, err
	}
	roleID = strings.TrimSpace(roleID)
	role, found, err := scoped.RoleByID(ctx, roleID)
	if err != nil {
		return identitymodel.IdentityRoleGovernanceDetail{}, err
	}
	if !found {
		return identitymodel.IdentityRoleGovernanceDetail{}, apperror.New(apperror.KindNotFound, "backend.identity.role_not_found", nil, map[string]string{"role": roleID})
	}
	definition, _ := scoped.PublishedRoleDefinition(ctx, role.Key)
	permissions, err := scoped.ListRolePermissionAssignments(ctx, role.ID)
	if err != nil {
		return identitymodel.IdentityRoleGovernanceDetail{}, err
	}
	fieldPermissions, err := scoped.ListRoleFieldPermissions(ctx, role.ID)
	if err != nil {
		return identitymodel.IdentityRoleGovernanceDetail{}, err
	}
	menuAssignments, err := scoped.ListRoleMenuAssignments(ctx, role.ID)
	if err != nil {
		return identitymodel.IdentityRoleGovernanceDetail{}, err
	}
	allMenus, err := scoped.ListMenus(ctx)
	if err != nil {
		return identitymodel.IdentityRoleGovernanceDetail{}, err
	}
	allAssignments, err := scoped.ListUserRoleAssignments(ctx, "")
	if err != nil {
		return identitymodel.IdentityRoleGovernanceDetail{}, err
	}

	menuIDs := make(map[string]bool, len(menuAssignments))
	for _, assignment := range menuAssignments {
		menuIDs[assignment.MenuID] = true
	}
	menus := make([]identitymodel.IdentityMenu, 0, len(menuAssignments))
	for _, menu := range allMenus {
		if menuIDs[menu.ID] || menuIDs[menu.Key] {
			menus = append(menus, menu)
		}
	}
	members := make([]identitymodel.IdentityUserRoleAssignment, 0)
	for _, assignment := range allAssignments {
		if assignment.RoleID == role.ID || assignment.RoleID == role.Key {
			members = append(members, assignment)
		}
	}

	permissionSetKeys := stringSet(definition.PermissionSetKeys)
	groupKeys := stringSet(definition.PermissionSetGroups)
	guardrailKeys := stringSet(definition.GuardrailKeys)
	permissionSets := filterPermissionSets(scoped.PublishedPermissionSets(ctx), permissionSetKeys)
	groups := filterPermissionSetGroups(scoped.PublishedPermissionSetGroups(ctx), groupKeys)
	for _, group := range groups {
		for _, key := range group.PermissionSetKeys {
			permissionSetKeys[key] = true
		}
	}
	permissionSets = filterPermissionSets(scoped.PublishedPermissionSets(ctx), permissionSetKeys)
	guardrails := filterGuardrails(scoped.PublishedGuardrails(ctx), guardrailKeys)
	guardrails = append(guardrails, definition.Guardrails...)

	return identitymodel.IdentityRoleGovernanceDetail{
		Role: role, Definition: definition,
		PermissionSets: permissionSets, PermissionSetGroups: groups, Guardrails: guardrails,
		Permissions: permissions, FieldPermissions: fieldPermissions,
		ExportRules: definition.ExportRules, Menus: menus, Members: members,
	}, nil
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = true
		}
	}
	return set
}

func filterPermissionSets(values []identitymodel.IdentityPermissionSet, keys map[string]bool) []identitymodel.IdentityPermissionSet {
	filtered := make([]identitymodel.IdentityPermissionSet, 0, len(keys))
	for _, value := range values {
		if keys[value.Key] {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func filterPermissionSetGroups(values []identitymodel.IdentityPermissionSetGroup, keys map[string]bool) []identitymodel.IdentityPermissionSetGroup {
	filtered := make([]identitymodel.IdentityPermissionSetGroup, 0, len(keys))
	for _, value := range values {
		if keys[value.Key] {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func filterGuardrails(values []identitymodel.IdentityGuardrailPolicy, keys map[string]bool) []identitymodel.IdentityGuardrailPolicy {
	filtered := make([]identitymodel.IdentityGuardrailPolicy, 0, len(keys))
	for _, value := range values {
		if keys[value.Key] {
			filtered = append(filtered, value)
		}
	}
	return filtered
}
