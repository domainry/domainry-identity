package identity

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

func (s *SQLIdentityStore) RemoveIdentityMenusAtomically(ctx context.Context, workspaceID string, menus []identitymodel.IdentityMenu) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, menu := range menus {
		if err := s.removeIdentityMenuStatements(ctx, tx, workspaceID, menu, true); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) ListIdentityMenus(ctx context.Context, workspaceID string) ([]identitymodel.IdentityMenu, error) {
	return s.loadMenus(ctx, workspaceID)
}

func (s *SQLIdentityStore) UpsertIdentityMenu(ctx context.Context, workspaceID string, menu identitymodel.IdentityMenu) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
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
	var persistedStatus string
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_menus", workspaceID).Columns("status").Where(ormbuilder.Equal("id", menu.ID)).Build()
	if err != nil {
		return fmt.Errorf("build identity menu status query: %w", err)
	}
	err = s.db.QueryRowContext(ctx, statement, arguments...).Scan(&persistedStatus)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if identitymodel.IdentityStatus(persistedStatus) == identitymodel.IdentityStatusDeleted {
		return nil
	}
	now := nowString()
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.sqlRenderer(), "identity_menus", workspaceID).
		Columns("id", "menu_key", "label", "description", "route", "icon", "parent_id", "sort_order", "status", "created_at", "updated_at").
		Values(menu.ID, menu.Key, menu.Label, menu.Description, menu.Route, menu.Icon, nullableText(menu.ParentID), menu.SortOrder, string(menu.Status), now, now)
	s.engineProfile().ApplyUpsert(insert, []string{"workspace_id", "id"}, "menu_key", "label", "description", "route", "icon", "parent_id", "sort_order", "status", "updated_at")
	statement, arguments, err = insert.Build()
	if err != nil {
		return fmt.Errorf("build identity menu upsert: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) RemoveIdentityMenu(ctx context.Context, workspaceID, menuID string) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	menus, err := s.ListIdentityMenus(ctx, workspaceID)
	if err != nil {
		return err
	}
	var menu identitymodel.IdentityMenu
	found := false
	for _, candidate := range menus {
		if candidate.ID == menuID {
			menu = candidate
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("menu not found: %s", menuID)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.removeIdentityMenuStatements(ctx, tx, workspaceID, menu, false); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) removeIdentityMenuStatements(ctx context.Context, execer identityUserExecer, workspaceID string, menu identitymodel.IdentityMenu, requireAffected bool) error {
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(s.sqlRenderer(), "identity_role_menu_assignments", workspaceID).
		Where(ormbuilder.In("menu_id", menu.ID, menu.Key)).Build()
	if err != nil {
		return fmt.Errorf("build identity menu assignment delete: %w", err)
	}
	if _, err := execer.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	statement, arguments, err = ormbuilder.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "identity_menus", workspaceID).
		Set("status", string(identitymodel.IdentityStatusDeleted)).Set("updated_at", nowString()).Where(ormbuilder.Equal("id", menu.ID)).Build()
	if err != nil {
		return fmt.Errorf("build identity menu soft delete: %w", err)
	}
	result, err := execer.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	if requireAffected {
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("menu not found: %s", menu.ID)
		}
	}
	return nil
}

func (s *SQLIdentityStore) SetIdentityRoleMenus(ctx context.Context, workspaceID, roleID string, menuIDs []string) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(s.sqlRenderer(), "identity_role_menu_assignments", workspaceID).Where(ormbuilder.Equal("role_id", roleID)).Build()
	if err != nil {
		return fmt.Errorf("build identity role-menu reset: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	now := nowString()
	menuIDs = uniqueSortedStrings(menuIDs)
	if len(menuIDs) == 0 {
		return nil
	}
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.sqlRenderer(), "identity_role_menu_assignments", workspaceID).Columns("id", "role_id", "menu_id", "created_at", "updated_at")
	for _, menuID := range menuIDs {
		insert.Values(identityID("rolemenu", workspaceID, roleID, menuID), roleID, menuID, now, now)
	}
	statement, arguments, err = insert.Build()
	if err != nil {
		return fmt.Errorf("build identity role-menu insert: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *SQLIdentityStore) ListIdentityRoleMenuAssignments(ctx context.Context, workspaceID, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return s.loadRoleMenuAssignments(ctx, workspaceID, roleID)
}

func (s *SQLIdentityStore) loadMenus(ctx context.Context, workspaceID string) ([]identitymodel.IdentityMenu, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_menus", workspaceID).
		Columns("id", "menu_key", "label", "description", "route", "icon", "parent_id", "sort_order", "status").
		Where(ormbuilder.NotEqual("status", string(identitymodel.IdentityStatusDeleted))).OrderBy(ormbuilder.Ascending("sort_order"), ormbuilder.Ascending("menu_key")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity menus query: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityMenu{}
	for rows.Next() {
		var menu identitymodel.IdentityMenu
		var parentID sql.NullString
		var status string
		if err := rows.Scan(&menu.ID, &menu.Key, &menu.Label, &menu.Description, &menu.Route, &menu.Icon, &parentID, &menu.SortOrder, &status); err != nil {
			return nil, err
		}
		menu.ParentID = valueFromNull(parentID)
		menu.Status = identitymodel.IdentityStatus(status)
		out = append(out, menu)
	}
	return out, rows.Err()
}

func (s *SQLIdentityStore) loadRoleMenuAssignments(ctx context.Context, workspaceID, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_role_menu_assignments", workspaceID).Columns("role_id", "menu_id")
	if strings.TrimSpace(roleID) != "" {
		builder.Where(ormbuilder.Equal("role_id", roleID))
	}
	statement, arguments, err := builder.OrderBy(ormbuilder.Ascending("role_id"), ormbuilder.Ascending("menu_id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity role-menu assignments query: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityRoleMenuAssignment{}
	for rows.Next() {
		var assignment identitymodel.IdentityRoleMenuAssignment
		if err := rows.Scan(&assignment.RoleID, &assignment.MenuID); err != nil {
			return nil, err
		}
		out = append(out, assignment)
	}
	return out, rows.Err()
}
