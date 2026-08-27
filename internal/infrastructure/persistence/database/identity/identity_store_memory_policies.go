package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) RemoveIdentityMenusAtomically(_ context.Context, workspaceID string, menus []identitymodel.IdentityMenu) error {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := map[string]bool{}
	for _, menu := range menus {
		if _, ok := s.menus[prefix+menu.ID]; !ok {
			return fmt.Errorf("menu not found: %s", menu.ID)
		}
		removed[menu.ID], removed[menu.Key] = true, true
	}
	for _, menu := range menus {
		delete(s.menus, prefix+menu.ID)
	}
	for roleID, menuIDs := range s.roleMenus {
		if !strings.HasPrefix(roleID, prefix) {
			continue
		}
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
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]identitymodel.IdentityMenu, 0, len(s.menus))
	for key, value := range s.menus {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
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
	key, err := identityWorkspaceKey(workspaceID, menu.ID)
	if err != nil {
		return err
	}
	if menu.ID == "" {
		return fmt.Errorf("menu id is required")
	}
	if menu.Key == "" {
		menu.Key = menu.ID
	}
	if menu.Status == "" {
		menu.Status = identitymodel.IdentityStatusActive
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.menus[key] = menu
	return nil
}

func (s *MemoryIdentityStore) RemoveIdentityMenu(ctx context.Context, workspaceID, menuID string) error {
	key, err := identityWorkspaceKey(workspaceID, menuID)
	if err != nil {
		return err
	}
	prefix, _ := identityWorkspacePrefix(workspaceID)
	s.mu.Lock()
	defer s.mu.Unlock()
	menu, ok := s.menus[key]
	if !ok {
		return fmt.Errorf("menu not found: %s", menuID)
	}
	delete(s.menus, key)
	for roleID, menuIDs := range s.roleMenus {
		if !strings.HasPrefix(roleID, prefix) {
			continue
		}
		filtered := make([]string, 0, len(menuIDs))
		for _, assigned := range menuIDs {
			if assigned != menu.ID && assigned != menu.Key {
				filtered = append(filtered, assigned)
			}
		}
		s.roleMenus[roleID] = filtered
	}
	return nil
}

func (s *MemoryIdentityStore) SetIdentityRoleMenus(ctx context.Context, workspaceID, roleID string, menuIDs []string) error {
	key, err := identityWorkspaceKey(workspaceID, roleID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roleMenus[key] = uniqueSortedStrings(menuIDs)
	return nil
}

func (s *MemoryIdentityStore) ListIdentityRoleMenuAssignments(ctx context.Context, workspaceID, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []identitymodel.IdentityRoleMenuAssignment{}
	appendAssignments := func(currentRoleID string, menuIDs []string) {
		for _, menuID := range menuIDs {
			out = append(out, identitymodel.IdentityRoleMenuAssignment{RoleID: currentRoleID, MenuID: menuID})
		}
	}
	if strings.TrimSpace(roleID) != "" {
		appendAssignments(roleID, s.roleMenus[prefix+roleID])
		return out, nil
	}
	roleIDs := make([]string, 0, len(s.roleMenus))
	for scopedRoleID := range s.roleMenus {
		if strings.HasPrefix(scopedRoleID, prefix) {
			roleIDs = append(roleIDs, strings.TrimPrefix(scopedRoleID, prefix))
		}
	}
	sort.Strings(roleIDs)
	for _, currentRoleID := range roleIDs {
		appendAssignments(currentRoleID, s.roleMenus[prefix+currentRoleID])
	}
	return out, nil
}
