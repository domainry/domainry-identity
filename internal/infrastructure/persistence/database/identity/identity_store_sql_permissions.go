package identity

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
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
		deleteAssignments := "DELETE FROM " + s.tableIdentifier("identity_role_menu_assignments") + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1) + " AND " + s.identifier("menu_id") + " IN (" + s.placeholder(2) + ", " + s.placeholder(3) + ")"
		if _, err := tx.ExecContext(ctx, deleteAssignments, workspaceID, menu.ID, menu.Key); err != nil {
			return err
		}
		updateMenu := "UPDATE " + s.tableIdentifier("identity_menus") + " SET " + s.identifier("status") + " = " + s.placeholder(1) + ", " + s.identifier("updated_at") + " = " + s.placeholder(2) + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(3) + " AND " + s.identifier("id") + " = " + s.placeholder(4)
		result, err := tx.ExecContext(ctx, updateMenu, string(identitymodel.IdentityStatusDeleted), nowString(), workspaceID, menu.ID)
		if err != nil {
			return err
		}
		if count, _ := result.RowsAffected(); count != 1 {
			return fmt.Errorf("menu not found: %s", menu.ID)
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
	err = s.db.QueryRowContext(ctx,
		"SELECT "+s.identifier("status")+" FROM "+s.tableIdentifier("identity_menus")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2),
		workspaceID, menu.ID,
	).Scan(&persistedStatus)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if identitymodel.IdentityStatus(persistedStatus) == identitymodel.IdentityStatusDeleted {
		return nil
	}
	now := nowString()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_menus")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2), workspaceID, menu.ID); err != nil {
		return err
	}
	query := "INSERT INTO " + s.tableIdentifier("identity_menus") + " (" + s.identityColumns("id", "workspace_id", "menu_key", "label", "description", "route", "icon", "parent_id", "sort_order", "status", "created_at", "updated_at") + ") VALUES (" + s.placeholders(12) + ")"
	if _, err := s.db.ExecContext(ctx, query, menu.ID, workspaceID, menu.Key, menu.Label, menu.Description, menu.Route, menu.Icon, nullableText(menu.ParentID), menu.SortOrder, string(menu.Status), now, now); err != nil {
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
	deleteAssignments := "DELETE FROM " + s.tableIdentifier("identity_role_menu_assignments") + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1) + " AND " + s.identifier("menu_id") + " IN (" + s.placeholder(2) + ", " + s.placeholder(3) + ")"
	if _, err := tx.ExecContext(ctx, deleteAssignments, workspaceID, menu.ID, menu.Key); err != nil {
		return err
	}
	updateMenu := "UPDATE " + s.tableIdentifier("identity_menus") + " SET " + s.identifier("status") + " = " + s.placeholder(1) + ", " + s.identifier("updated_at") + " = " + s.placeholder(2) + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(3) + " AND " + s.identifier("id") + " = " + s.placeholder(4)
	if _, err := tx.ExecContext(ctx, updateMenu, string(identitymodel.IdentityStatusDeleted), nowString(), workspaceID, menu.ID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) SetIdentityRoleMenus(ctx context.Context, workspaceID, roleID string, menuIDs []string) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_role_menu_assignments")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("role_id")+" = "+s.placeholder(2), workspaceID, roleID); err != nil {
		return err
	}
	now := nowString()
	query := "INSERT INTO " + s.tableIdentifier("identity_role_menu_assignments") + " (" + s.identityColumns("id", "workspace_id", "role_id", "menu_id", "created_at", "updated_at") + ") VALUES (" + s.placeholders(6) + ")"
	for _, menuID := range uniqueSortedStrings(menuIDs) {
		if _, err := s.db.ExecContext(ctx, query, identityID("rolemenu", workspaceID, roleID, menuID), workspaceID, roleID, menuID, now, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLIdentityStore) ListIdentityRoleMenuAssignments(ctx context.Context, workspaceID, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return s.loadRoleMenuAssignments(ctx, workspaceID, roleID)
}

func (s *SQLIdentityStore) loadMenus(ctx context.Context, workspaceID string) ([]identitymodel.IdentityMenu, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+s.identityColumns("id", "menu_key", "label", "description", "route", "icon", "parent_id", "sort_order", "status")+" FROM "+s.tableIdentifier("identity_menus")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("status")+" <> "+s.placeholder(2)+" ORDER BY "+s.identifier("sort_order")+", "+s.identifier("menu_key"), workspaceID, string(identitymodel.IdentityStatusDeleted))
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
	query := "SELECT " + s.identityColumns("role_id", "menu_id") + " FROM " + s.tableIdentifier("identity_role_menu_assignments")
	args := []any{workspaceID}
	query += " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1)
	if strings.TrimSpace(roleID) != "" {
		args = append(args, roleID)
		query += " AND " + s.identifier("role_id") + " = " + s.placeholder(2)
	}
	query += " ORDER BY " + s.identifier("role_id") + ", " + s.identifier("menu_id")
	rows, err := s.db.QueryContext(ctx, query, args...)
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
