package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *SQLIdentityStore) ListIdentityDepartments(ctx context.Context, workspaceID string) ([]identitymodel.IdentityDepartment, error) {
	return s.loadDepartments(ctx, workspaceID)
}

func (s *SQLIdentityStore) UpsertIdentityDepartment(ctx context.Context, workspaceID string, department identitymodel.IdentityDepartment) error {
	return s.writeIdentityDepartment(ctx, s.db, workspaceID, department)
}

func (s *SQLIdentityStore) writeIdentityDepartment(ctx context.Context, execer identityUserExecer, workspaceID string, department identitymodel.IdentityDepartment) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if department.ID == "" {
		return fmt.Errorf("department id is required")
	}
	if department.Status == "" {
		department.Status = identitymodel.IdentityStatusActive
	}
	ancestorRaw, _ := json.Marshal(department.AncestorIDs)
	parentID := nullableString(department.ParentID)
	now := nowString()
	if _, err := execer.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_departments")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2), workspaceID, department.ID); err != nil {
		return err
	}
	query := "INSERT INTO " + s.tableIdentifier("identity_departments") + " (" + s.identityColumns("id", "workspace_id", "name", "parent_id", "leader_workforce_profile_id", "path", "ancestor_ids", "depth", "sort_order", "status", "created_at", "updated_at") + ") VALUES (" + s.placeholders(12) + ")"
	if _, err := execer.ExecContext(ctx, query, department.ID, workspaceID, department.Name, parentID, nullableText(department.LeaderWorkforceProfileID), department.Path, string(ancestorRaw), department.Depth, department.SortOrder, string(department.Status), now, now); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) ListIdentityUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	return s.loadUsers(ctx, workspaceID)
}

func (s *SQLIdentityStore) ListIdentityProfileBindingsByUser(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityProfileBinding, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	columns := s.identityColumns("workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at")
	query := "SELECT " + columns + " FROM " + s.tableIdentifier("identity_profile_bindings") +
		" WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1) +
		" AND " + s.identifier("identity_user_id") + " = " + s.placeholder(2) +
		" ORDER BY " + s.identifier("object_key") + ", " + s.identifier("profile_id")
	rows, err := s.reader(ctx).QueryContext(ctx, query, workspaceID, strings.TrimSpace(userID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := []identitymodel.IdentityProfileBinding{}
	for rows.Next() {
		binding, err := scanIdentityProfileBinding(rows)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

func (s *SQLIdentityStore) GetIdentityUser(ctx context.Context, workspaceID, userID string) (identitymodel.IdentityUser, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	columns := s.identityColumns(
		"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at",
	)
	query := "SELECT " + columns + " FROM " + s.tableIdentifier("identity_users") +
		" WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1) +
		" AND " + s.identifier("id") + " = " + s.placeholder(2)
	user, err := scanIdentityUser(s.reader(ctx).QueryRowContext(ctx, query, workspaceID, strings.TrimSpace(userID)))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityUser{}, false, nil
	}
	return user, err == nil, err
}

func (s *SQLIdentityStore) UpsertIdentityUser(ctx context.Context, workspaceID string, user identitymodel.IdentityUser) error {
	return s.writeIdentityUser(ctx, s.db, workspaceID, user)
}

func (s *SQLIdentityStore) UpdateIdentityUserLocale(ctx context.Context, workspaceID, userID, locale string, expectedVersion int64) (identitymodel.IdentityUser, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	result, err := s.db.ExecContext(ctx,
		"UPDATE "+s.tableIdentifier("identity_users")+" SET "+s.identifier("locale")+" = "+s.placeholder(1)+", "+s.identifier("version")+" = "+s.identifier("version")+" + 1, "+s.identifier("updated_at")+" = "+s.placeholder(2)+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(3)+" AND "+s.identifier("id")+" = "+s.placeholder(4)+" AND "+s.identifier("version")+" = "+s.placeholder(5),
		locale, nowString(), workspaceID, userID, expectedVersion,
	)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	if rows != 1 {
		return identitymodel.IdentityUser{}, false, nil
	}
	user, found, err := s.GetIdentityUser(ctx, workspaceID, userID)
	return user, found, err
}

func (s *SQLIdentityStore) UpsertIdentityUsersAtomically(ctx context.Context, workspaceID string, users []identitymodel.IdentityUser) error {
	if _, err := identityWorkspaceID(workspaceID); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, user := range users {
		if err := s.writeIdentityUser(ctx, tx, workspaceID, user); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

type identityUserExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SQLIdentityStore) writeIdentityUser(ctx context.Context, execer identityUserExecer, workspaceID string, user identitymodel.IdentityUser) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if user.ID == "" {
		return fmt.Errorf("user id is required")
	}
	if user.Status == "" {
		user.Status = identitymodel.IdentityStatusActive
	}
	if user.AccountType == "" {
		user.AccountType = identitymodel.IdentityAccountHuman
	}
	now := nowString()
	var existingVersion int64
	var existingCreatedAt string
	existingErr := execer.QueryRowContext(
		ctx,
		"SELECT "+s.identityColumns("version", "created_at")+" FROM "+s.tableIdentifier("identity_users")+
			" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2),
		workspaceID, user.ID,
	).Scan(&existingVersion, &existingCreatedAt)
	switch existingErr {
	case nil:
		user.Version = existingVersion + 1
		user.CreatedAt = existingCreatedAt
	case sql.ErrNoRows:
		user.Version = 1
		user.CreatedAt = now
	default:
		return existingErr
	}
	user.UpdatedAt = now
	if _, err := execer.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_users")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2), workspaceID, user.ID); err != nil {
		return err
	}
	columns := s.identityColumns(
		"id", "workspace_id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at",
	)
	query := "INSERT INTO " + s.tableIdentifier("identity_users") + " (" + columns + ") VALUES (" + s.placeholders(19) + ")"
	_, err = execer.ExecContext(ctx, query,
		user.ID, workspaceID, user.Name, user.GivenName, user.MiddleName, user.FamilyName, user.NamePrefix, user.NameSuffix, user.NativeName, user.NameLocale,
		user.Email, user.Phone, string(user.AccountType), user.Locale, user.Timezone, string(user.Status), user.Version, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

func (s *SQLIdentityStore) UpsertIdentityUserWithRoleAssignmentsAtomically(
	ctx context.Context,
	workspaceID string,
	user identitymodel.IdentityUser,
	assignments []identitymodel.IdentityUserRoleAssignment,
) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.writeIdentityUser(ctx, tx, workspaceID, user); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM "+s.tableIdentifier("identity_user_role_assignments")+
			" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+
			" AND "+s.identifier("user_id")+" = "+s.placeholder(2),
		workspaceID, user.ID,
	); err != nil {
		return err
	}
	for _, assignment := range assignments {
		if err := s.writeIdentityUserRoleAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLIdentityStore) RemoveIdentityUser(ctx context.Context, workspaceID, userID string) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{
		"identity_user_role_assignments",
		"identity_credentials",
		"identity_external_accounts",
		"identity_mfa_factors",
		"auth_refresh_tokens",
	} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier(table)+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("user_id")+" = "+s.placeholder(2), workspaceID, userID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_users")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2), workspaceID, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLIdentityStore) SetIdentityUserStatus(ctx context.Context, workspaceID, userID string, status identitymodel.IdentityStatus) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "UPDATE "+s.tableIdentifier("identity_users")+" SET "+s.identifier("status")+" = "+s.placeholder(1)+", "+s.identifier("version")+" = "+s.identifier("version")+" + 1, "+s.identifier("updated_at")+" = "+s.placeholder(2)+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(3)+" AND "+s.identifier("id")+" = "+s.placeholder(4), string(status), nowString(), workspaceID, userID)
	return err
}

func (s *SQLIdentityStore) loadDepartments(ctx context.Context, workspaceID string) ([]identitymodel.IdentityDepartment, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	rows, err := s.reader(ctx).QueryContext(ctx, "SELECT "+s.identityColumns("id", "name", "parent_id", "leader_workforce_profile_id", "path", "ancestor_ids", "depth", "sort_order", "status")+" FROM "+s.tableIdentifier("identity_departments")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" ORDER BY "+s.identifier("depth")+", "+s.identifier("parent_id")+", "+s.identifier("sort_order")+", "+s.identifier("id"), workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityDepartment{}
	for rows.Next() {
		var department identitymodel.IdentityDepartment
		var parentID sql.NullString
		var leaderWorkforceProfileID sql.NullString
		var ancestorRaw string
		if err := rows.Scan(&department.ID, &department.Name, &parentID, &leaderWorkforceProfileID, &department.Path, &ancestorRaw, &department.Depth, &department.SortOrder, &department.Status); err != nil {
			return nil, err
		}
		department.ParentID = pointerFromNull(parentID)
		department.LeaderWorkforceProfileID = leaderWorkforceProfileID.String
		_ = json.Unmarshal([]byte(ancestorRaw), &department.AncestorIDs)
		out = append(out, department)
	}
	return out, rows.Err()
}

func (s *SQLIdentityStore) loadUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	columns := s.identityColumns(
		"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at",
	)
	rows, err := s.reader(ctx).QueryContext(ctx, "SELECT "+columns+" FROM "+s.tableIdentifier("identity_users")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" ORDER BY "+s.identifier("id"), workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityUser{}
	for rows.Next() {
		user, err := scanIdentityUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, user)
	}
	return out, rows.Err()
}

func scanIdentityUser(scanner interface{ Scan(...any) error }) (identitymodel.IdentityUser, error) {
	var user identitymodel.IdentityUser
	var accountType, status string
	err := scanner.Scan(
		&user.ID, &user.Name, &user.GivenName, &user.MiddleName, &user.FamilyName, &user.NamePrefix, &user.NameSuffix, &user.NativeName, &user.NameLocale,
		&user.Email, &user.Phone, &accountType, &user.Locale, &user.Timezone, &status, &user.Version, &user.CreatedAt, &user.UpdatedAt,
	)
	user.AccountType = identitymodel.IdentityAccountType(accountType)
	user.Status = identitymodel.IdentityStatus(status)
	return user, err
}
