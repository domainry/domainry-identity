package identity

import (
	"regexp"
	"strings"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

var businessRouteKeyPattern = regexp.MustCompile(`^business\.[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

// WithStandaloneIdentityRoleDefinitions supplies the authorization authority
// required by the built-in Admin users when a standalone Identity manifest is
// intentionally empty. Project-published definitions with the same key win.
func WithStandaloneIdentityRoleDefinitions(configured []identitymodel.RoleSchema) []identitymodel.RoleSchema {
	organizationPermissions := make([]string, 0)
	for _, permission := range identitycontract.IdentityPlatformPermissionKeys() {
		if strings.HasPrefix(permission, "identity.") || strings.HasPrefix(permission, "audit.") || strings.HasPrefix(permission, "metadata.") {
			organizationPermissions = append(organizationPermissions, permission)
		}
	}
	defaults := []identitymodel.RoleSchema{
		{
			Key: "admin", Name: "Admin", Permissions: []string{"workspace.admin"}, RecordScope: "all_records",
			Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
			RiskLevel: identitymodel.IdentityRoleRiskPrivileged, GrantableRoleKeys: []string{"*"},
		},
		{
			Key: "organization_administrator", Name: "Organization administrator", Permissions: organizationPermissions, RecordScope: "all_records",
			Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
			RiskLevel: identitymodel.IdentityRoleRiskPrivileged, GrantableRoleKeys: []string{"*"},
		},
		{
			Key: "system_administrator", Name: "System administrator",
			Permissions: []string{"identity.audit.view", "audit.governance.read", "audit.governance.export", "metadata.read", "metadata.write"},
			RecordScope: "all_records", Audience: identitymodel.IdentityRoleAudienceAny,
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
		"org_users", "org_workforce", "org_departments", "org_roles", "org_menus",
		"org_data_scopes", "org_field_permissions", "system", "system_metadata", "system_audit",
	)...)
	roleMenus = append(roleMenus, generatedIdentityRoleMenusForIDs("system_administrator", platformMenus,
		"system", "system_metadata", "system_audit",
	)...)
	return Seed{
		Permissions: generatedGlobalPermissionDefinitions(generatedGlobalPermissionKeys()),
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
	add("org_workforce", "Workforce", "/admin/org/workforce", "briefcase-business", "org_access", 220)
	add("org_departments", "Departments", "/admin/org/departments", "building-2", "org_access", 230)
	add("org_roles", "Roles", "/admin/org/roles", "user-cog", "org_access", 240)
	add("org_menus", "Menus", "/admin/org/menus", "square-menu", "org_access", 250)
	add("org_data_scopes", "Data scopes", "/admin/org/data-scopes", "shield-check", "org_access", 260)
	add("org_field_permissions", "Field permissions", "/admin/org/field-permissions", "columns-3", "org_access", 270)
	add("system_metadata", "Metadata", "/admin/system/metadata", "database", "system", 380)
	add("system_audit", "Governance audit", "/admin/system/audit", "scroll-text", "system", 390)
	return menus
}

func requiredPermissionsForAdminRoute(route string) ([]string, bool) {
	return identitycontract.AdminRouteRequiredPermissions(route)
}

// requiredPermissionsForMenuRoute keeps Admin URLs under the platform Admin
// registry while Business Workspace menus reference the stable route_key from
// the project-published Route Registry. Literal /business URLs are rejected so
// Identity never becomes a second owner of project frontend paths.
func requiredPermissionsForMenuRoute(route string) ([]string, bool) {
	route = strings.TrimSpace(route)
	if businessRouteKeyPattern.MatchString(route) {
		return []string{}, true
	}
	return requiredPermissionsForAdminRoute(route)
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

func generatedGlobalPermissionKeys() []string {
	return identitycontract.IdentityPlatformPermissionKeys()
}

// RuntimeGlobalPermissionKeys exposes the concrete platform permission
// registry used by Runtime identity discovery. Object and Business Action
// permission templates are resolved from project metadata instead.
func RuntimeGlobalPermissionKeys() []string {
	return append([]string(nil), generatedGlobalPermissionKeys()...)
}

func generatedGlobalPermissionDefinitions(keys []string) []identitymodel.IdentityPermissionDefinition {
	definitions := make([]identitymodel.IdentityPermissionDefinition, 0, len(keys))
	for _, key := range keys {
		system, resource, action := IdentityParsePermissionKey(key)
		definitions = append(definitions, identitymodel.IdentityPermissionDefinition{
			Key:           key,
			Label:         IdentityHumanizeIdentifier(resource + " " + action),
			System:        system,
			Resource:      resource,
			ResourceLabel: IdentityHumanizeIdentifier(resource),
			Action:        action,
			Category:      "Global system capability",
			Description:   IdentityHumanizeIdentifier(system + " " + resource + " " + action),
		})
	}
	return definitions
}
