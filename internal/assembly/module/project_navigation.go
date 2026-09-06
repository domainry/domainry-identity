package moduleassembly

import (
	"context"
	"fmt"
	"sort"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

type workspaceBootstrapNavigationCatalog struct {
	catalog identitysdk.ProjectNavigationCatalog
	sha256  string
}

// BindBootstrapProjectNavigationCatalog binds the build-produced navigation
// file without writing Workspace-owned rows. Bootstrap later materializes one
// isolated copy per Workspace in the host-owned transaction.
func (binding *moduleBinding) BindBootstrapProjectNavigationCatalog(ctx context.Context, catalog identitysdk.ProjectNavigationCatalog) error {
	if binding == nil || binding.runtime == nil || binding.runtime.Identity == nil || binding.runtime.IdentityStore == nil {
		return &identitysdk.Error{Code: "identity.bootstrap_project_navigation_catalog_unavailable"}
	}
	if ctx == nil {
		return &identitysdk.Error{Code: "identity.context_required"}
	}
	if err := ctx.Err(); err != nil {
		return &identitysdk.Error{Code: "identity.context_unavailable", Cause: err}
	}
	normalized, err := identitysdk.NormalizeProjectNavigationCatalog(catalog)
	if err != nil {
		return &identitysdk.Error{Code: "identity.bootstrap_project_navigation_catalog_invalid", Cause: err}
	}
	digest, err := identitysdk.ProjectNavigationCatalogSHA256(normalized)
	if err != nil {
		return &identitysdk.Error{Code: "identity.bootstrap_project_navigation_catalog_invalid", Cause: err}
	}

	binding.bootstrapMu.Lock()
	defer binding.bootstrapMu.Unlock()
	provisionableRoles := make(map[string]bool, len(binding.bootstrapRoleCatalog.roles))
	for _, role := range binding.bootstrapRoleCatalog.roles {
		provisionableRoles[strings.TrimSpace(role.Key)] = true
	}
	for _, roleMenus := range normalized.RoleMenuSets {
		if !provisionableRoles[roleMenus.RoleKey] {
			return &identitysdk.Error{Code: "identity.bootstrap_project_navigation_role_unknown", Params: map[string]string{"role_key": roleMenus.RoleKey}}
		}
	}
	binding.bootstrapNavigationCatalog = workspaceBootstrapNavigationCatalog{catalog: normalized, sha256: digest}
	return nil
}

func emptyWorkspaceBootstrapNavigationCatalog() workspaceBootstrapNavigationCatalog {
	catalog := identitysdk.ProjectNavigationCatalog{ContractVersion: identitysdk.ProjectNavigationContractVersion, Menus: []identitysdk.ProjectMenuDefinition{}}
	normalized, err := identitysdk.NormalizeProjectNavigationCatalog(catalog)
	if err != nil {
		panic("normalize empty project navigation catalog: " + err.Error())
	}
	digest, err := identitysdk.ProjectNavigationCatalogSHA256(normalized)
	if err != nil {
		panic("digest empty project navigation catalog: " + err.Error())
	}
	return workspaceBootstrapNavigationCatalog{catalog: normalized, sha256: digest}
}

func (binding *moduleBinding) workspaceBootstrapNavigationCatalogSnapshot() workspaceBootstrapNavigationCatalog {
	binding.bootstrapMu.Lock()
	defer binding.bootstrapMu.Unlock()
	stored := binding.bootstrapNavigationCatalog
	normalized, err := identitysdk.NormalizeProjectNavigationCatalog(stored.catalog)
	if err != nil {
		return workspaceBootstrapNavigationCatalog{}
	}
	return workspaceBootstrapNavigationCatalog{catalog: normalized, sha256: stored.sha256}
}

func workspaceBootstrapNavigation(workspaceID string, catalog workspaceBootstrapNavigationCatalog) ([]identitymodel.IdentityMenu, []identitymodel.IdentityRoleMenuAssignment, error) {
	if strings.TrimSpace(catalog.sha256) == "" || catalog.catalog.ContractVersion != identitysdk.ProjectNavigationContractVersion {
		return nil, nil, &identitysdk.Error{Code: "identity.workspace_bootstrap_navigation_catalog_unavailable"}
	}
	menuIDs := make(map[string]string, len(catalog.catalog.Menus))
	for _, definition := range catalog.catalog.Menus {
		menuIDs[definition.Key] = identitypersistence.WorkspaceMenuID(workspaceID, definition.Key)
	}
	menus := make([]identitymodel.IdentityMenu, 0, len(catalog.catalog.Menus))
	for _, definition := range catalog.catalog.Menus {
		label := projectNavigationLabel(definition.Label)
		if label == "" {
			return nil, nil, &identitysdk.Error{Code: "identity.workspace_bootstrap_navigation_catalog_invalid", Params: map[string]string{"menu_key": definition.Key}}
		}
		menus = append(menus, identitymodel.IdentityMenu{
			ID: menuIDs[definition.Key], Key: definition.Key, Label: label,
			Description: definition.Description, Route: definition.Route, Icon: definition.Icon,
			ParentID: menuIDs[definition.ParentKey], SortOrder: definition.SortOrder, Status: identitymodel.IdentityStatusActive,
		})
	}
	assignments := make([]identitymodel.IdentityRoleMenuAssignment, 0)
	for _, roleMenus := range catalog.catalog.RoleMenuSets {
		roleID := identitypersistence.WorkspaceRoleID(workspaceID, roleMenus.RoleKey)
		for _, menuKey := range roleMenus.MenuKeys {
			assignments = append(assignments, identitymodel.IdentityRoleMenuAssignment{RoleID: roleID, MenuID: menuIDs[menuKey]})
		}
	}
	return menus, assignments, nil
}

func projectNavigationLabel(labels map[string]string) string {
	if value := strings.TrimSpace(labels["en"]); value != "" {
		return value
	}
	if value := strings.TrimSpace(labels["zh-CN"]); value != "" {
		return value
	}
	locales := make([]string, 0, len(labels))
	for locale := range labels {
		locales = append(locales, locale)
	}
	sort.Strings(locales)
	for _, locale := range locales {
		if value := strings.TrimSpace(labels[locale]); value != "" {
			return value
		}
	}
	return ""
}

var _ identitysdk.BootstrapProjectNavigationCatalogBinder = (*moduleBinding)(nil)

func validateWorkspaceBootstrapNavigationRoles(roleCatalog workspaceBootstrapRoleCatalog, navigationCatalog workspaceBootstrapNavigationCatalog) error {
	known := make(map[string]bool, len(roleCatalog.roles))
	for _, role := range roleCatalog.roles {
		known[role.Key] = true
	}
	for _, relation := range navigationCatalog.catalog.RoleMenuSets {
		if !known[relation.RoleKey] {
			return fmt.Errorf("navigation role %q is not provisioned to workspaces", relation.RoleKey)
		}
	}
	return nil
}
