package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) RemoveIdentityMenusAtomically(_ context.Context, workspaceID string, menus []identitymodel.IdentityMenu) error {
	_ = workspaceID
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := map[string]bool{}
	for _, menu := range menus {
		if _, ok := s.menus[menu.MenuID]; !ok {
			return fmt.Errorf("menu not found: %s", menu.MenuID)
		}
		removed[menu.MenuID], removed[menu.Key] = true, true
	}
	for _, menu := range menus {
		delete(s.menus, menu.MenuID)
	}
	for roleID, menuIDs := range s.roleMenus {
		filtered := make([]string, 0, len(menuIDs))
		for _, assigned := range menuIDs {
			if !removed[assigned] {
				filtered = append(filtered, assigned)
			}
		}
		s.roleMenus[roleID] = filtered
	}
	return nil
}

func (s *MemoryIdentityStore) ListIdentityMenus(ctx context.Context, workspaceID string) ([]identitymodel.IdentityMenu, error) {
	_ = ctx
	_ = workspaceID
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]identitymodel.IdentityMenu, 0, len(s.menus))
	for _, value := range s.menus {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SortOrder == out[j].SortOrder {
			return out[i].Key < out[j].Key
		}
		return out[i].SortOrder < out[j].SortOrder
	})
	return out, nil
}

func (s *MemoryIdentityStore) UpsertIdentityMenu(ctx context.Context, workspaceID string, menu identitymodel.IdentityMenu) error {
	_ = ctx
	_ = workspaceID
	if menu.MenuID == "" {
		return fmt.Errorf("menu id is required")
	}
	if menu.Key == "" {
		menu.Key = menu.MenuID
	}
	if menu.Status == "" {
		menu.Status = identitymodel.IdentityStatusActive
	}
	menu.SourceOwner = strings.TrimSpace(menu.SourceOwner)
	if menu.SourceOwner == "" {
		return fmt.Errorf("menu source owner is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.menus[menu.MenuID] = menu
	return nil
}

func (s *MemoryIdentityStore) RemoveIdentityMenu(ctx context.Context, workspaceID, menuID string) error {
	_ = ctx
	_ = workspaceID
	s.mu.Lock()
	defer s.mu.Unlock()
	menu, ok := s.menus[menuID]
	if !ok {
		return fmt.Errorf("menu not found: %s", menuID)
	}
	delete(s.menus, menuID)
	for roleID, menuIDs := range s.roleMenus {
		filtered := make([]string, 0, len(menuIDs))
		for _, assigned := range menuIDs {
			if assigned != menu.MenuID && assigned != menu.Key {
				filtered = append(filtered, assigned)
			}
		}
		s.roleMenus[roleID] = filtered
	}
	return nil
}

func (s *MemoryIdentityStore) SetIdentityRoleMenus(ctx context.Context, workspaceID, roleID string, menuIDs []string) error {
	_ = ctx
	_ = workspaceID
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roleMenus[roleID] = uniqueSortedStrings(menuIDs)
	return nil
}

func (s *MemoryIdentityStore) ListIdentityRoleMenuAssignments(ctx context.Context, workspaceID, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	_ = ctx
	_ = workspaceID
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []identitymodel.IdentityRoleMenuAssignment{}
	appendAssignments := func(currentRoleID string, menuIDs []string) {
		for _, menuID := range menuIDs {
			out = append(out, identitymodel.IdentityRoleMenuAssignment{RoleID: currentRoleID, MenuID: menuID})
		}
	}
	if strings.TrimSpace(roleID) != "" {
		appendAssignments(roleID, s.roleMenus[roleID])
		return out, nil
	}
	roleIDs := make([]string, 0, len(s.roleMenus))
	for currentRoleID := range s.roleMenus {
		roleIDs = append(roleIDs, currentRoleID)
	}
	sort.Strings(roleIDs)
	for _, currentRoleID := range roleIDs {
		appendAssignments(currentRoleID, s.roleMenus[currentRoleID])
	}
	return out, nil
}
