package identity

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

var businessRouteKeyPattern = regexp.MustCompile(`^business\.[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

// platformAdminNavigationSource is the Identity-owned machine contract also
// shipped with the unified Admin frontend. Runtime seed data and page-level
// permission validation must be derived from this document rather than from
// independently maintained lists.
//
//go:embed platform_admin_navigation_v9.json
var platformAdminNavigationSource []byte

//go:embed platform_admin_role_menus_v1.json
var platformAdminRoleMenusSource []byte

type platformAdminNavigationContract struct {
	ContractVersion string `json:"contract_version"`
	Groups          []struct {
		Key       string            `json:"key"`
		MenuID    string            `json:"menu_id"`
		Label     map[string]string `json:"label"`
		Icon      string            `json:"icon"`
		SortOrder int               `json:"sort_order"`
	} `json:"groups"`
	Workspaces []struct {
		Key                 string            `json:"key"`
		Group               string            `json:"group"`
		Label               map[string]string `json:"label"`
		MenuID              string            `json:"menu_id"`
		MenuKey             string            `json:"menu_key"`
		Icon                string            `json:"icon"`
		Route               string            `json:"route"`
		SortOrder           int               `json:"sort_order"`
		RequiredPermissions []string          `json:"required_permissions"`
	} `json:"workspaces"`
}

type platformAdminRoleMenusContract struct {
	ContractVersion string `json:"contract_version"`
	RoleMenuSets    []struct {
		RoleKey  string   `json:"role_key"`
		MenuKeys []string `json:"menu_keys"`
	} `json:"role_menu_sets"`
}

var platformAdminNavigation = mustPlatformAdminNavigationContract()
var platformAdminRoleMenus = mustPlatformAdminRoleMenusContract()

func mustPlatformAdminNavigationContract() platformAdminNavigationContract {
	var contract platformAdminNavigationContract
	if err := json.Unmarshal(platformAdminNavigationSource, &contract); err != nil {
		panic("parse embedded platform Admin navigation contract: " + err.Error())
	}
	if contract.ContractVersion != "domainry-admin-navigation-workspaces-v9" || len(contract.Groups) == 0 || len(contract.Workspaces) == 0 {
		panic("embedded platform Admin navigation contract is incomplete")
	}
	return contract
}

func mustPlatformAdminRoleMenusContract() platformAdminRoleMenusContract {
	var contract platformAdminRoleMenusContract
	if err := json.Unmarshal(platformAdminRoleMenusSource, &contract); err != nil {
		panic("parse embedded platform Admin role-menu contract: " + err.Error())
	}
	if contract.ContractVersion != "domainry-admin-role-menu-sets-v1" || len(contract.RoleMenuSets) == 0 {
		panic("embedded platform Admin role-menu contract is incomplete")
	}
	knownMenus := make(map[string]bool, len(platformAdminNavigation.Groups)+len(platformAdminNavigation.Workspaces))
	for _, group := range platformAdminNavigation.Groups {
		knownMenus[group.MenuID] = true
	}
	for _, workspace := range platformAdminNavigation.Workspaces {
		knownMenus[workspace.MenuKey] = true
	}
	seenRoles := map[string]bool{}
	for _, set := range contract.RoleMenuSets {
		roleKey := strings.TrimSpace(set.RoleKey)
		if roleKey == "" || seenRoles[roleKey] {
			panic("embedded platform Admin role-menu contract has an invalid or duplicated role")
		}
		seenRoles[roleKey] = true
		seenMenus := map[string]bool{}
		for _, menuKey := range set.MenuKeys {
			menuKey = strings.TrimSpace(menuKey)
			if !knownMenus[menuKey] || seenMenus[menuKey] {
				panic("embedded platform Admin role-menu contract has an invalid or duplicated menu")
			}
			seenMenus[menuKey] = true
		}
	}
	return contract
}

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
			Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
			RiskLevel: identitymodel.IdentityRoleRiskPrivileged, GrantableRoleKeys: []string{"*"},
		},
		{
			Key: "organization_administrator", Name: "Organization administrator", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, organizationPermissionKeys...),
			Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
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
	roleMenus := generatedIdentityRoleMenusFromTemplate(platformMenus)
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
	menus := make([]identitymodel.IdentityMenu, 0, len(platformAdminNavigation.Groups)+len(platformAdminNavigation.Workspaces))
	groupIDs := make(map[string]string, len(platformAdminNavigation.Groups))
	for _, group := range platformAdminNavigation.Groups {
		groupIDs[group.Key] = group.MenuID
		menus = append(menus, identitymodel.IdentityMenu{
			ID:        group.MenuID,
			Key:       group.MenuID,
			Label:     group.Label["en"],
			Icon:      group.Icon,
			SortOrder: group.SortOrder,
			Status:    identitymodel.IdentityStatusActive,
		})
	}
	for _, workspace := range platformAdminNavigation.Workspaces {
		menus = append(menus, identitymodel.IdentityMenu{
			ID:        workspace.MenuID,
			Key:       workspace.MenuKey,
			Label:     workspace.Label["en"],
			Route:     workspace.Route,
			Icon:      workspace.Icon,
			ParentID:  groupIDs[workspace.Group],
			SortOrder: workspace.SortOrder,
			Status:    identitymodel.IdentityStatusActive,
		})
	}
	return menus
}

// identityBuiltinPagePermissions is the standalone/test fallback. Production
// assembly injects the complete frozen registry, including module pages.
type identityBuiltinPagePermissions struct{}

func (identityBuiltinPagePermissions) RequiredPermissionsForPage(route string) ([]string, bool) {
	if permissions, ok := platformAdminPagePermissions(route); ok {
		return permissions, true
	}
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

// platformAdminPagePermissions is the stable product-route projection used by
// Identity's menu governance. The frontend still owns layout and navigation;
// this map only lets Runtime validate that a role assigned a platform menu also
// owns every entry permission required by that page.
func platformAdminPagePermissions(route string) ([]string, bool) {
	route = strings.TrimSpace(route)
	for _, workspace := range platformAdminNavigation.Workspaces {
		if workspace.Route == route {
			return append([]string(nil), workspace.RequiredPermissions...), true
		}
	}
	return nil, false
}

func generatedIdentityRoleMenusFromTemplate(menus []identitymodel.IdentityMenu) []identitymodel.IdentityRoleMenuAssignment {
	menuIDsByKey := make(map[string]string, len(menus))
	for _, menu := range menus {
		menuIDsByKey[menu.Key] = menu.ID
	}
	assignments := make([]identitymodel.IdentityRoleMenuAssignment, 0)
	for _, set := range platformAdminRoleMenus.RoleMenuSets {
		for _, menuKey := range set.MenuKeys {
			assignments = append(assignments, identitymodel.IdentityRoleMenuAssignment{
				RoleID: strings.TrimSpace(set.RoleKey), MenuID: menuIDsByKey[strings.TrimSpace(menuKey)],
			})
		}
	}
	return assignments
}
