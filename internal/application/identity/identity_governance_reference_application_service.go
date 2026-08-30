package identity

import (
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"

	"context"
	"fmt"
	"strings"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (validator *IdentityGovernanceApplicationService) validateFieldPermissions(values []identitymodel.IdentityFieldPermission) []identitycontract.IdentityGovernanceValidationIssue {
	issues := []identitycontract.IdentityGovernanceValidationIssue{}
	seen := map[string]bool{}
	objects := validator.businessObjects()
	for index, value := range values {
		resource, field := strings.TrimSpace(value.Resource), strings.TrimSpace(value.Field)
		path := fmt.Sprintf("field_permissions[%d]", index)
		key := resource + "\x00" + field
		object, objectExists := objects[resource]
		if !objectExists {
			issues = append(issues, identityGovernanceIssue("field_permissions", path+".resource", "backend.identity.field_permission_resource_not_found", "identity.role_field_permission", map[string]string{"resource": resource, "actual": resource}))
		} else if !identityObjectHasField(object, field) {
			issues = append(issues, identityGovernanceIssue("field_permissions", path+".field", "backend.identity.field_permission_field_not_found", "identity.role_field_permission", map[string]string{"resource": resource, "field": field, "actual": field}))
		}
		if resource != "" && field != "" && seen[key] {
			issues = append(issues, identityGovernanceIssue("field_permissions", path, "backend.identity.field_permission_duplicate", "identity.role_field_permission", map[string]string{"resource": resource, "field": field}))
		}
		if value.Editable && !value.Visible {
			issues = append(issues, identityGovernanceIssue("field_permissions", path+".editable", "backend.identity.field_permission_edit_requires_visibility", "identity.role_field_permission", map[string]string{"expected": "visible=true", "actual": "visible=false"}))
		}
		seen[key] = true
	}
	return issues
}

func identityObjectHasField(object definitionmodel.ObjectSchema, fieldKey string) bool {
	for _, field := range object.Fields {
		if strings.TrimSpace(field.Key) == fieldKey {
			return true
		}
	}
	return false
}

func (validator *IdentityGovernanceApplicationService) validateRole(ctx context.Context, workspaceID string, role identitymodel.IdentityRole) ([]identitycontract.IdentityGovernanceValidationIssue, error) {
	issues := []identitycontract.IdentityGovernanceValidationIssue{}
	role.ID, role.Key = strings.TrimSpace(role.ID), strings.ToLower(strings.TrimSpace(role.Key))
	if role.ID == "" {
		issues = append(issues, identityGovernanceIssue("role", "role.id", "backend.identity.role_id_key_required", "identity.role", map[string]string{"field": "id"}))
	}
	if role.Key == "" {
		issues = append(issues, identityGovernanceIssue("role", "role.key", "backend.identity.role_id_key_required", "identity.role", map[string]string{"field": "key"}))
	}
	roles, err := validator.repository.ListIdentityRoles(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	for _, existing := range roles {
		if existing.ID != role.ID && strings.EqualFold(strings.TrimSpace(existing.Key), role.Key) {
			issues = append(issues, identityGovernanceIssue("role", "role.key", "backend.identity.role_key_exists", "identity.role", map[string]string{"role": role.Key, "actual": role.Key}))
			break
		}
	}
	return issues, nil
}

func (validator *IdentityGovernanceApplicationService) validateMenu(ctx context.Context, workspaceID string, menu identitymodel.IdentityMenu) ([]identitycontract.IdentityGovernanceValidationIssue, error) {
	issues := []identitycontract.IdentityGovernanceValidationIssue{}
	menu.ID, menu.Key, menu.ParentID = strings.TrimSpace(menu.ID), strings.TrimSpace(menu.Key), strings.TrimSpace(menu.ParentID)
	if menu.ID == "" {
		menu.ID = menu.Key
	}
	if menu.Key == "" {
		menu.Key = menu.ID
	}
	if menu.ID == "" {
		issues = append(issues, identityGovernanceIssue("menu", "menu.key", "backend.identity.menu_id_key_required", "identity.menu", nil))
		return issues, nil
	}
	menus, err := validator.repository.ListIdentityMenus(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	byID := map[string]identitymodel.IdentityMenu{menu.ID: menu}
	for _, existing := range menus {
		byID[existing.ID] = existing
		if existing.ID != menu.ID && strings.EqualFold(strings.TrimSpace(existing.Key), menu.Key) {
			issues = append(issues, identityGovernanceIssue("menu", "menu.key", "backend.identity.menu_key_exists", "identity.menu", map[string]string{"menu": menu.Key, "actual": menu.Key}))
		}
	}
	if menu.ParentID == menu.ID {
		issues = append(issues, identityGovernanceIssue("menu", "menu.parent_id", "backend.identity.menu_parent_self", "identity.menu", map[string]string{"menu": menu.ID}))
	} else if menu.ParentID != "" {
		issues = append(issues, validateMenuParentChain(menu, byID)...)
	}
	return issues, nil
}

func validateMenuParentChain(menu identitymodel.IdentityMenu, byID map[string]identitymodel.IdentityMenu) []identitycontract.IdentityGovernanceValidationIssue {
	seen := map[string]bool{menu.ID: true}
	for cursor := menu.ParentID; cursor != ""; {
		if seen[cursor] {
			return []identitycontract.IdentityGovernanceValidationIssue{identityGovernanceIssue("menu", "menu.parent_id", "backend.identity.menu_parent_cycle", "identity.menu", map[string]string{"menu": menu.ID})}
		}
		seen[cursor] = true
		parent, exists := byID[cursor]
		if !exists {
			return []identitycontract.IdentityGovernanceValidationIssue{identityGovernanceIssue("menu", "menu.parent_id", "backend.identity.menu_parent_not_found", "identity.menu", map[string]string{"parent_id": cursor, "actual": cursor})}
		}
		cursor = strings.TrimSpace(parent.ParentID)
	}
	return nil
}

func (validator *IdentityGovernanceApplicationService) validateMenuReferences(ctx context.Context, workspaceID string, menuIDs []string) ([]identitycontract.IdentityGovernanceValidationIssue, error) {
	menus, err := validator.repository.ListIdentityMenus(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	known, seen := map[string]bool{}, map[string]bool{}
	for _, menu := range menus {
		known[menu.ID], known[menu.Key] = true, true
	}
	issues := []identitycontract.IdentityGovernanceValidationIssue{}
	for index, raw := range menuIDs {
		menuID := strings.TrimSpace(raw)
		path := fmt.Sprintf("menu_ids[%d]", index)
		if menuID == "" {
			issues = append(issues, identityGovernanceIssue("menus", path, "backend.identity.menu_not_found", "identity.role_menu_assignment", map[string]string{"menu": menuID, "actual": raw}))
		} else if seen[menuID] {
			issues = append(issues, identityGovernanceIssue("menus", path, "backend.identity.menu_assignment_duplicate", "identity.role_menu_assignment", map[string]string{"actual": raw}))
		} else if !known[menuID] {
			issues = append(issues, identityGovernanceIssue("menus", path, "backend.identity.menu_not_found", "identity.role_menu_assignment", map[string]string{"menu": menuID, "actual": menuID}))
		}
		seen[menuID] = true
	}
	return issues, nil
}
