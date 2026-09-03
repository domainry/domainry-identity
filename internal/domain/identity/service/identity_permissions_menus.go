package service

import (
	"context"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func (s *IdentityDomainService) ListRolePermissionAssignments(ctx context.Context, roleID string) ([]identitymodel.IdentityRolePermissionAssignment, error) {
	if role, published, err := s.publishedRoleForIdentifier(ctx, roleID); err != nil {
		return nil, err
	} else if published {
		assignments := make([]identitymodel.IdentityRolePermissionAssignment, 0, len(role.Permissions))
		for _, permission := range role.Permissions {
			if key := strings.TrimSpace(permission.PermissionKey); key != "" && permission.DataScope.Valid() {
				assignments = append(assignments, identitymodel.IdentityRolePermissionAssignment{RoleID: roleID, PermissionKey: key, DataScope: permission.DataScope, AuditDenial: permission.AuditDenial})
			}
		}
		return assignments, nil
	}
	return []identitymodel.IdentityRolePermissionAssignment{}, nil
}

func (s *IdentityDomainService) ListRoleFieldPermissions(ctx context.Context, roleID string) ([]identitymodel.IdentityFieldPermission, error) {
	if role, published, err := s.publishedRoleForIdentifier(ctx, roleID); err != nil {
		return nil, err
	} else if published {
		values := make([]identitymodel.IdentityFieldPermission, 0, len(role.FieldPermissions))
		for _, permission := range role.FieldPermissions {
			if objectKey, fieldKey := strings.TrimSpace(permission.ObjectKey), strings.TrimSpace(permission.FieldKey); objectKey != "" && fieldKey != "" {
				values = append(values, identitymodel.IdentityFieldPermission{Resource: objectKey, Field: fieldKey, Visible: permission.Read, Editable: permission.Write, Masked: permission.Masked, Policies: cloneContextualFieldPolicies(permission.Policies)})
			}
		}
		return values, nil
	}
	return []identitymodel.IdentityFieldPermission{}, nil
}

func (s *IdentityDomainService) publishedRoleForIdentifier(ctx context.Context, roleID string) (identitymodel.RoleSchema, bool, error) {
	role, ok, err := s.roleByID(ctx, roleID)
	if err != nil || !ok {
		return identitymodel.RoleSchema{}, false, err
	}
	published, ok := s.publishedRoleDefinition(role)
	return published, ok, nil
}

func (s *IdentityDomainService) UpsertMenu(ctx context.Context, menu identitymodel.IdentityMenu) error {
	menu.ID = strings.TrimSpace(menu.ID)
	menu.Key = strings.TrimSpace(menu.Key)
	menu.ParentID = strings.TrimSpace(menu.ParentID)
	if menu.ID == "" {
		menu.ID = menu.Key
	}
	if menu.Key == "" {
		menu.Key = menu.ID
	}
	if menu.ID == "" {
		return badRequest("backend.identity.menu_id_key_required")
	}
	if menu.Label == "" {
		menu.Label = menu.Key
	}
	if menu.Status == "" {
		menu.Status = identitymodel.IdentityStatusActive
	}
	menus, err := s.repo.ListIdentityMenus(ctx, s.workspace)
	if err != nil {
		return err
	}
	for _, existing := range menus {
		if existing.ID != menu.ID && strings.EqualFold(strings.TrimSpace(existing.Key), menu.Key) {
			return badRequest("backend.identity.menu_key_exists", "menu", menu.Key)
		}
	}
	if menu.ParentID != "" {
		if menu.ParentID == menu.ID {
			return badRequest("backend.identity.menu_parent_self", "menu", menu.ID)
		}
		byID := make(map[string]identitymodel.IdentityMenu, len(menus)+1)
		for _, existing := range menus {
			byID[existing.ID] = existing
		}
		byID[menu.ID] = menu
		_, ok := byID[menu.ParentID]
		if !ok {
			return badRequest("backend.identity.menu_parent_not_found", "parent_id", menu.ParentID)
		}
		seen := map[string]bool{menu.ID: true}
		cursor := menu.ParentID
		for cursor != "" {
			if seen[cursor] {
				return badRequest("backend.identity.menu_parent_cycle", "menu", menu.ID)
			}
			seen[cursor] = true
			parent, ok := byID[cursor]
			if !ok {
				return badRequest("backend.identity.menu_parent_not_found", "parent_id", cursor)
			}
			cursor = strings.TrimSpace(parent.ParentID)
		}
	}
	return s.repo.UpsertIdentityMenu(ctx, s.workspace, menu)
}

func (s *IdentityDomainService) RemoveMenu(ctx context.Context, menuID string) ([]string, error) {
	menuID = strings.TrimSpace(menuID)
	menus, err := s.repo.ListIdentityMenus(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]identitymodel.IdentityMenu, len(menus))
	var target identitymodel.IdentityMenu
	for _, menu := range menus {
		byID[menu.ID] = menu
		if menu.ID == menuID || menu.Key == menuID {
			target = menu
		}
	}
	if target.ID == "" {
		return nil, notFound("backend.identity.menu_not_found", "menu", menuID)
	}
	deleted := []string{}
	deleteMenus := []identitymodel.IdentityMenu{}
	var collectChildrenFirst func(string)
	collectChildrenFirst = func(parentID string) {
		for _, menu := range menus {
			if strings.TrimSpace(menu.ParentID) == parentID {
				collectChildrenFirst(menu.ID)
			}
		}
		menu := byID[parentID]
		deleted = append(deleted, parentID)
		deleteMenus = append(deleteMenus, menu)
		delete(byID, parentID)
	}
	collectChildrenFirst(target.ID)
	atomic, ok := s.repo.(identityrepository.IdentityAtomicMutationRepository)
	if !ok {
		return nil, fmt.Errorf("backend.identity.atomic_mutation_repository_unavailable")
	}
	if err := atomic.RemoveIdentityMenusAtomically(ctx, s.workspace, deleteMenus); err != nil {
		return nil, err
	}
	return deleted, nil
}

func (s *IdentityDomainService) SetRoleMenus(ctx context.Context, roleID string, menuIDs []string) error {
	if _, ok, err := s.roleByID(ctx, roleID); err != nil {
		return err
	} else if !ok {
		return badRequest("backend.identity.role_not_found", "role", roleID)
	}
	menus, err := s.repo.ListIdentityMenus(ctx, s.workspace)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, menu := range menus {
		known[menu.ID] = true
		known[menu.Key] = true
	}
	for _, menuID := range menuIDs {
		menuID = strings.TrimSpace(menuID)
		if menuID == "" {
			continue
		}
		if !known[menuID] {
			return badRequest("backend.identity.menu_not_found", "menu", menuID)
		}
	}
	return s.repo.SetIdentityRoleMenus(ctx, s.workspace, roleID, menuIDs)
}

func (s *IdentityDomainService) ListRoleMenuAssignments(ctx context.Context, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return s.repo.ListIdentityRoleMenuAssignments(ctx, s.workspace, roleID)
}
