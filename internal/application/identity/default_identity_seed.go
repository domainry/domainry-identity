package identity

import (
	"regexp"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

var businessRouteKeyPattern = regexp.MustCompile(`^business\.[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

// WithStandaloneIdentityRoleDefinitions supplies the authorization authority
// required by the built-in Admin users when a standalone Identity manifest is
// intentionally empty. Project-published definitions with the same key win.
func WithStandaloneIdentityRoleDefinitions(configured []identitymodel.RoleSchema) []identitymodel.RoleSchema {
	organizationPermissionKeys := make([]string, 0)
	for _, action := range IdentityBuiltinAuthorizationActions() {
		if action.Permission != nil {
			organizationPermissionKeys = append(organizationPermissionKeys, action.Key)
		}
	}
	defaults := []identitymodel.RoleSchema{
		{
			Key: "admin", Name: "Admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, organizationPermissionKeys...),
			Audience:        identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
			RiskLevel: identitymodel.IdentityRoleRiskPrivileged, GrantableRoleKeys: []string{"*"},
		},
		{
			Key: "organization_administrator", Name: "Organization administrator", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, organizationPermissionKeys...),
			Audience:        identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
			RiskLevel: identitymodel.IdentityRoleRiskPrivileged, GrantableRoleKeys: []string{"*"},
		},
		{
			Key: "system_administrator", Name: "System administrator",
			Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll,
				"audit.governance.read", "audit.governance.export",
				"identity.metadata.manifest.get", "identity.metadata.reload",
				"identity.metadata.migration_plan.get", "identity.metadata.object_record_count.get",
				"identity.metadata.definition.validate", "identity.metadata.definition.upsert",
				"identity.metadata.definition.disable", "identity.metadata.definition.rollback",
			),
			Audience:       identitymodel.IdentityRoleAudienceAny,
			AssignmentMode: identitymodel.IdentityRoleAssignmentManual, RiskLevel: identitymodel.IdentityRoleRiskElevated,
		},
	}
	byKey := make(map[string]int, len(defaults)+len(configured))
	result := append([]identitymodel.RoleSchema(nil), defaults...)
	for index := range result {
		byKey[result[index].Key] = index
	}
	for _, role := range configured {
		role.Key = strings.TrimSpace(role.Key)
		if role.Key == "" {
			continue
		}
		if index, exists := byKey[role.Key]; exists {
			result[index] = role
			continue
		}
		byKey[role.Key] = len(result)
		result = append(result, role)
	}
	return result
}

func identityValueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func generatedManifestIdentitySeed() Seed {
	platformMenus := generatedIdentityMenus()
	roleMenus := generatedIdentityRoleMenus("admin", platformMenus)
	roleMenus = append(roleMenus, generatedIdentityRoleMenusForIDs("organization_administrator", platformMenus,
		"org_users", "org_organization_units", "org_roles", "org_menus",
		"org_field_permissions", "system", "system_metadata", "system_audit",
	)...)
	roleMenus = append(roleMenus, generatedIdentityRoleMenusForIDs("system_administrator", platformMenus,
		"system", "system_metadata", "system_audit",
	)...)
	return Seed{
		Roles: []identitymodel.IdentityRole{
			{ID: "admin", Key: "admin", Label: "Admin", Status: identitymodel.IdentityStatusActive},
			{ID: "organization_administrator", Key: "organization_administrator", Label: "Organization administrator", Status: identitymodel.IdentityStatusActive},
			{ID: "system_administrator", Key: "system_administrator", Label: "System administrator", Status: identitymodel.IdentityStatusActive},
		},
		Users: []identitymodel.IdentityUser{{
			ID:     "admin",
			Name:   "Admin",
			Email:  "admin@example.com",
			Status: identitymodel.IdentityStatusActive,
		}},
		UserRoles: []identitymodel.IdentityUserRoleAssignment{{
			UserID: "admin",
			RoleID: "admin",
		}},
		Menus:     platformMenus,
		RoleMenus: roleMenus,
	}
}

func generatedIdentityMenus() []identitymodel.IdentityMenu {
	menus := []identitymodel.IdentityMenu{
		{ID: "org_access", Key: "org_access", Label: "Organization & access", SortOrder: 100, Status: identitymodel.IdentityStatusActive},
		{ID: "system", Key: "system", Label: "Identity metadata", SortOrder: 200, Status: identitymodel.IdentityStatusActive},
	}
	add := func(key, label, route, icon, parent string, sort int) {
		menus = append(menus, identitymodel.IdentityMenu{
			ID:        key,
			Key:       key,
			Label:     label,
			Route:     route,
			Icon:      icon,
			ParentID:  parent,
			SortOrder: sort,
			Status:    identitymodel.IdentityStatusActive,
		})
	}
	add("org_users", "Accounts", "/admin/security/accounts", "users-round", "org_access", 210)
	add("org_organization_units", "Organization units", "/admin/org/organization-units", "building-2", "org_access", 220)
	add("org_roles", "Roles", "/admin/org/roles", "user-cog", "org_access", 240)
	add("org_menus", "Menus", "/admin/org/menus", "square-menu", "org_access", 250)
	add("org_field_permissions", "Field permissions", "/admin/org/field-permissions", "columns-3", "org_access", 270)
	add("system_metadata", "Metadata", "/admin/system/metadata", "database", "system", 380)
	add("system_audit", "Governance audit", "/admin/system/audit", "scroll-text", "system", 390)
	return menus
}

// identityBuiltinPagePermissions is the standalone/test fallback. Production
// assembly injects the complete frozen registry, including module pages.
type identityBuiltinPagePermissions struct{}

func (identityBuiltinPagePermissions) RequiredPermissionsForPage(route string) ([]string, bool) {
	route = strings.TrimSpace(route)
	for _, action := range IdentityBuiltinAuthorizationActions() {
		if action.Permission == nil || action.Permission.Key != action.Key {
			continue
		}
		for _, page := range action.Pages {
			if page.Route == route {
				return []string{action.Key}, true
			}
		}
	}
	return nil, false
}

func generatedIdentityRoleMenus(roleID string, menus []identitymodel.IdentityMenu) []identitymodel.IdentityRoleMenuAssignment {
	assignments := make([]identitymodel.IdentityRoleMenuAssignment, 0, len(menus))
	for _, menu := range menus {
		if strings.TrimSpace(menu.ID) == "" {
			continue
		}
		assignments = append(assignments, identitymodel.IdentityRoleMenuAssignment{RoleID: roleID, MenuID: menu.ID})
	}
	return assignments
}

func generatedIdentityRoleMenusForIDs(roleID string, menus []identitymodel.IdentityMenu, menuIDs ...string) []identitymodel.IdentityRoleMenuAssignment {
	allowed := make(map[string]bool, len(menuIDs))
	for _, menuID := range menuIDs {
		allowed[menuID] = true
	}
	assignments := make([]identitymodel.IdentityRoleMenuAssignment, 0, len(menuIDs))
	for _, menu := range menus {
		if allowed[menu.ID] {
			assignments = append(assignments, identitymodel.IdentityRoleMenuAssignment{RoleID: roleID, MenuID: menu.ID})
		}
	}
	return assignments
}
