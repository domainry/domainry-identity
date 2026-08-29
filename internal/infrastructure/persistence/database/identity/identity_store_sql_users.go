package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
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
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.sqlRenderer(), "identity_departments", workspaceID).
		Columns("id", "name", "parent_id", "leader_workforce_profile_id", "path", "ancestor_ids", "depth", "sort_order", "status", "created_at", "updated_at").
		Values(department.ID, department.Name, parentID, nullableText(department.LeaderWorkforceProfileID), department.Path, string(ancestorRaw), department.Depth, department.SortOrder, string(department.Status), now, now)
	s.engineProfile().ApplyUpsert(insert, []string{"workspace_id", "id"}, "name", "parent_id", "leader_workforce_profile_id", "path", "ancestor_ids", "depth", "sort_order", "status", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity department upsert: %w", err)
	}
	if _, err := execer.ExecContext(ctx, statement, arguments...); err != nil {
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
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_profile_bindings", workspaceID).
		Columns("workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at").
		Where(ormbuilder.Equal("identity_user_id", strings.TrimSpace(userID))).OrderBy(ormbuilder.Ascending("object_key"), ormbuilder.Ascending("profile_id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity profile bindings by user query: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
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
	statement, arguments, err := identityUserSelect(s, workspaceID).Where(ormbuilder.Equal("id", strings.TrimSpace(userID))).Build()
	if err != nil {
		return identitymodel.IdentityUser{}, false, fmt.Errorf("build identity user query: %w", err)
	}
	user, err := scanIdentityUser(s.reader(ctx).QueryRowContext(ctx, statement, arguments...))
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
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "identity_users", workspaceID).
		Set("locale", locale).SetExpression("version", ormbuilder.Add(ormbuilder.Column("version"), ormbuilder.Value(1))).Set("updated_at", nowString()).
		Where(ormbuilder.And(ormbuilder.Equal("id", userID), ormbuilder.Equal("version", expectedVersion))).Build()
	if err != nil {
		return identitymodel.IdentityUser{}, false, fmt.Errorf("build identity user locale update: %w", err)
	}
	result, err := s.db.ExecContext(ctx, statement, arguments...)
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
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_users", workspaceID).
		Columns("version", "created_at").Where(ormbuilder.Equal("id", user.ID)).Build()
	if err != nil {
		return fmt.Errorf("build identity user version query: %w", err)
	}
	existingErr := execer.QueryRowContext(ctx, statement, arguments...).Scan(&existingVersion, &existingCreatedAt)
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
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.sqlRenderer(), "identity_users", workspaceID).
		Columns("id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at").
		Values(user.ID, user.Name, user.GivenName, user.MiddleName, user.FamilyName, user.NamePrefix, user.NameSuffix, user.NativeName, user.NameLocale,
			user.Email, user.Phone, string(user.AccountType), user.Locale, user.Timezone, string(user.Status), user.Version, user.CreatedAt, user.UpdatedAt,
		)
	s.engineProfile().ApplyUpsert(insert, []string{"workspace_id", "id"}, "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "status", "version", "updated_at")
	statement, arguments, err = insert.Build()
	if err != nil {
		return fmt.Errorf("build identity user upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
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
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(s.sqlRenderer(), "identity_user_role_assignments", workspaceID).Where(ormbuilder.Equal("user_id", user.ID)).Build()
	if err != nil {
		return fmt.Errorf("build identity user role reset: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
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
		statement, arguments, buildErr := ormbuilder.NewWorkspaceDeleteBuilder(s.sqlRenderer(), table, workspaceID).Where(ormbuilder.Equal("user_id", userID)).Build()
		if buildErr != nil {
			return fmt.Errorf("build identity user relation delete: %w", buildErr)
		}
		if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
			return err
		}
	}
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(s.sqlRenderer(), "identity_users", workspaceID).Where(ormbuilder.Equal("id", userID)).Build()
	if err != nil {
		return fmt.Errorf("build identity user delete: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLIdentityStore) SetIdentityUserStatus(ctx context.Context, workspaceID, userID string, status identitymodel.IdentityStatus) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "identity_users", workspaceID).
		Set("status", string(status)).SetExpression("version", ormbuilder.Add(ormbuilder.Column("version"), ormbuilder.Value(1))).Set("updated_at", nowString()).
		Where(ormbuilder.Equal("id", userID)).Build()
	if err != nil {
		return fmt.Errorf("build identity user status update: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *SQLIdentityStore) loadDepartments(ctx context.Context, workspaceID string) ([]identitymodel.IdentityDepartment, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_departments", workspaceID).
		Columns("id", "name", "parent_id", "leader_workforce_profile_id", "path", "ancestor_ids", "depth", "sort_order", "status").
		OrderBy(ormbuilder.Ascending("depth"), ormbuilder.Ascending("parent_id"), ormbuilder.Ascending("sort_order"), ormbuilder.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity departments query: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
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
	statement, arguments, err := identityUserSelect(s, workspaceID).OrderBy(ormbuilder.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity users query: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
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

func identityUserSelect(s *SQLIdentityStore, workspaceID string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_users", workspaceID).Columns(
		"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at",
	)
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
