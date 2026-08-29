package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	menupersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/authorization/menu"
)

func (s *SQLIdentityStore) menuStore() *menupersistence.Store {
	return menupersistence.New(s, nowString)
}

func (s *SQLIdentityStore) RemoveIdentityMenusAtomically(ctx context.Context, workspaceID string, menus []identitymodel.IdentityMenu) error {
	return s.menuStore().RemoveIdentityMenusAtomically(ctx, workspaceID, menus)
}

func (s *SQLIdentityStore) ListIdentityMenus(ctx context.Context, workspaceID string) ([]identitymodel.IdentityMenu, error) {
	return s.menuStore().ListIdentityMenus(ctx, workspaceID)
}

func (s *SQLIdentityStore) UpsertIdentityMenu(ctx context.Context, workspaceID string, menu identitymodel.IdentityMenu) error {
	return s.menuStore().UpsertIdentityMenu(ctx, workspaceID, menu)
}

func (s *SQLIdentityStore) RemoveIdentityMenu(ctx context.Context, workspaceID, menuID string) error {
	return s.menuStore().RemoveIdentityMenu(ctx, workspaceID, menuID)
}

func (s *SQLIdentityStore) SetIdentityRoleMenus(ctx context.Context, workspaceID, roleID string, menuIDs []string) error {
	return s.menuStore().SetIdentityRoleMenus(ctx, workspaceID, roleID, menuIDs)
}

func (s *SQLIdentityStore) ListIdentityRoleMenuAssignments(ctx context.Context, workspaceID, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return s.menuStore().ListIdentityRoleMenuAssignments(ctx, workspaceID, roleID)
}

func (s *SQLIdentityStore) loadMenus(ctx context.Context, workspaceID string) ([]identitymodel.IdentityMenu, error) {
	return s.menuStore().LoadMenus(ctx, workspaceID)
}

func (s *SQLIdentityStore) loadRoleMenuAssignments(ctx context.Context, workspaceID, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return s.menuStore().LoadRoleMenuAssignments(ctx, workspaceID, roleID)
}
