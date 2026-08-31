package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*query.InsertBuilder, []string, ...string) *query.InsertBuilder
	QueryIdentityContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryIdentityRowContext(context.Context, string, ...any) *sql.Row
}

type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type Store struct {
	backend Backend
	now     func() string
}

func New(backend Backend, now func() string) *Store { return &Store{backend: backend, now: now} }

func (s *Store) List(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := selectUsers(s.backend.SQLRenderer(), workspaceID).OrderBy(query.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity users query: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityUser{}
	for rows.Next() {
		item, scanErr := scan(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) Get(ctx context.Context, workspaceID, userID string) (identitymodel.IdentityUser, bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	statement, arguments, err := selectUsers(s.backend.SQLRenderer(), workspaceID).Where(query.Equal("id", strings.TrimSpace(userID))).Build()
	if err != nil {
		return identitymodel.IdentityUser{}, false, fmt.Errorf("build identity user query: %w", err)
	}
	item, err := scan(s.backend.QueryIdentityRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityUser{}, false, nil
	}
	return item, err == nil, err
}

func (s *Store) Upsert(ctx context.Context, execer Execer, workspaceID string, item identitymodel.IdentityUser) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	if item.ID == "" {
		return fmt.Errorf("user id is required")
	}
	if item.Status == "" {
		item.Status = identitymodel.IdentityStatusActive
	}
	if item.AccountType == "" {
		item.AccountType = identitymodel.IdentityAccountHuman
	}
	now := s.now()
	var version int64
	var createdAt string
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).Columns("version", "created_at").Where(query.Equal("id", item.ID)).Build()
	if err != nil {
		return fmt.Errorf("build identity user version query: %w", err)
	}
	switch existingErr := execer.QueryRowContext(ctx, statement, arguments...).Scan(&version, &createdAt); existingErr {
	case nil:
		item.Version, item.CreatedAt = version+1, createdAt
	case sql.ErrNoRows:
		item.Version, item.CreatedAt = 1, now
	default:
		return existingErr
	}
	item.UpdatedAt = now
	insert := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).Columns("id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at").Values(item.ID, item.Name, item.GivenName, item.MiddleName, item.FamilyName, item.NamePrefix, item.NameSuffix, item.NativeName, item.NameLocale, item.Email, item.Phone, string(item.AccountType), item.Locale, item.Timezone, string(item.Status), item.Version, item.CreatedAt, item.UpdatedAt)
	s.backend.ApplyUpsert(insert, []string{"workspace_id", "id"}, "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "status", "version", "updated_at")
	statement, arguments, err = insert.Build()
	if err != nil {
		return fmt.Errorf("build identity user upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) UpdateLocale(ctx context.Context, workspaceID, userID, locale string, expectedVersion int64) (identitymodel.IdentityUser, bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).Set("locale", locale).SetExpression("version", query.Add(query.Column("version"), query.Value(1))).Set("updated_at", s.now()).Where(query.And(query.Equal("id", userID), query.Equal("version", expectedVersion))).Build()
	if err != nil {
		return identitymodel.IdentityUser{}, false, fmt.Errorf("build identity user locale update: %w", err)
	}
	result, err := s.backend.DB().ExecContext(ctx, statement, arguments...)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	if count != 1 {
		return identitymodel.IdentityUser{}, false, nil
	}
	return s.Get(ctx, workspaceID, userID)
}

func (s *Store) UpsertMany(ctx context.Context, workspaceID string, items []identitymodel.IdentityUser) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		if err := s.Upsert(ctx, tx, workspaceID, item); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Remove(ctx context.Context, workspaceID, userID string) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"_identity_user_role_assignments", "_identity_credentials", "_identity_external_accounts", "_identity_mfa_factors", "_identity_auth_refresh_tokens"} {
		statement, arguments, buildErr := query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), table, workspaceID).Where(query.Equal("user_id", userID)).Build()
		if buildErr != nil {
			return fmt.Errorf("build identity user relation delete: %w", buildErr)
		}
		if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
			return err
		}
	}
	statement, arguments, err := query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).Where(query.Equal("id", userID)).Build()
	if err != nil {
		return fmt.Errorf("build identity user delete: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetStatus(ctx context.Context, workspaceID, userID string, status identitymodel.IdentityStatus) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).Set("status", string(status)).SetExpression("version", query.Add(query.Column("version"), query.Value(1))).Set("updated_at", s.now()).Where(query.Equal("id", userID)).Build()
	if err != nil {
		return fmt.Errorf("build identity user status update: %w", err)
	}
	_, err = s.backend.DB().ExecContext(ctx, statement, arguments...)
	return err
}

func selectUsers(renderer ormdialect.Renderer, workspaceID string) *query.SelectBuilder {
	return query.NewWorkspaceSelectBuilder(renderer, "_identity_users", workspaceID).Columns("id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at")
}
func scan(scanner interface{ Scan(...any) error }) (identitymodel.IdentityUser, error) {
	var item identitymodel.IdentityUser
	var accountType, status string
	err := scanner.Scan(&item.ID, &item.Name, &item.GivenName, &item.MiddleName, &item.FamilyName, &item.NamePrefix, &item.NameSuffix, &item.NativeName, &item.NameLocale, &item.Email, &item.Phone, &accountType, &item.Locale, &item.Timezone, &status, &item.Version, &item.CreatedAt, &item.UpdatedAt)
	item.AccountType, item.Status = identitymodel.IdentityAccountType(accountType), identitymodel.IdentityStatus(status)
	return item, err
}
func workspace(value string) (string, error) {
	id, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
