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
	return s.ListWithinDataScope(ctx, workspaceID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *Store) ListWithinDataScope(ctx context.Context, workspaceID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUser, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := selectUsers(s.backend.SQLRenderer(), workspaceID).OrderBy(query.Ascending("id"))
	applyUserDataScope(builder, scope)
	statement, arguments, err := builder.Build()
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
	return s.GetWithinDataScope(ctx, workspaceID, userID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *Store) GetWithinDataScope(ctx context.Context, workspaceID, userID string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityUser, bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	predicates := []query.Predicate{query.Equal("id", strings.TrimSpace(userID))}
	if !scope.Unrestricted {
		predicates = append(predicates, userDataScopePredicate(scope))
	}
	statement, arguments, err := selectUsers(s.backend.SQLRenderer(), workspaceID).Where(query.And(predicates...)).Build()
	if err != nil {
		return identitymodel.IdentityUser{}, false, fmt.Errorf("build identity user query: %w", err)
	}
	item, err := scan(s.backend.QueryIdentityRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityUser{}, false, nil
	}
	return item, err == nil, err
}

func applyUserDataScope(builder *query.SelectBuilder, scope identitymodel.IdentityDataScopeFilter) {
	if !scope.Unrestricted {
		builder.Where(userDataScopePredicate(scope))
	}
}

func userDataScopePredicate(scope identitymodel.IdentityDataScopeFilter) query.Predicate {
	scope = scope.Normalized()
	if scope.Unrestricted {
		return query.AlwaysTrue()
	}
	predicates := make([]query.Predicate, 0, 2)
	if len(scope.OwnerUserIDs) > 0 {
		values := make([]any, len(scope.OwnerUserIDs))
		for index := range scope.OwnerUserIDs {
			values[index] = scope.OwnerUserIDs[index]
		}
		predicates = append(predicates, query.In("id", values...))
	}
	if len(scope.OwnerOrgIDs) > 0 {
		values := make([]any, len(scope.OwnerOrgIDs))
		for index := range scope.OwnerOrgIDs {
			values[index] = scope.OwnerOrgIDs[index]
		}
		predicates = append(predicates, query.In("org_id", values...))
	}
	if len(predicates) == 0 {
		return query.AlwaysFalse()
	}
	return query.Or(predicates...)
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
	insert := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).
		Columns("id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "org_id", "support_org_id", "manager_user_id", "reporting_path", "worker_no", "worker_type", "work_status", "start_date", "end_date", "status", "version", "created_at", "updated_at").
		Values(item.ID, item.Name, item.GivenName, item.MiddleName, item.FamilyName, item.NamePrefix, item.NameSuffix, item.NativeName, item.NameLocale, item.Email, item.Phone, string(item.AccountType), item.Locale, item.Timezone, nullable(item.OrgID), nullable(item.SupportOrgID), nullable(item.ManagerUserID), item.ReportingPath, item.WorkerNo, string(item.WorkerType), string(item.WorkStatus), nullable(item.StartDate), nullable(item.EndDate), string(item.Status), item.Version, item.CreatedAt, item.UpdatedAt)
	s.backend.ApplyUpsert(insert, []string{"workspace_id", "id"}, "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "org_id", "support_org_id", "manager_user_id", "reporting_path", "worker_no", "worker_type", "work_status", "start_date", "end_date", "status", "version", "updated_at")
	statement, arguments, err = insert.Build()
	if err != nil {
		return fmt.Errorf("build identity user upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) Create(ctx context.Context, workspaceID string, item identitymodel.IdentityUser) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(item.ID) == "" {
		return fmt.Errorf("user id is required")
	}
	if item.Status == "" {
		item.Status = identitymodel.IdentityStatusActive
	}
	if item.AccountType == "" {
		item.AccountType = identitymodel.IdentityAccountHuman
	}
	now := s.now()
	item.Version, item.CreatedAt, item.UpdatedAt = 1, now, now
	insert := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).
		Columns("id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "org_id", "support_org_id", "manager_user_id", "reporting_path", "worker_no", "worker_type", "work_status", "start_date", "end_date", "status", "version", "created_at", "updated_at").
		Values(item.ID, item.Name, item.GivenName, item.MiddleName, item.FamilyName, item.NamePrefix, item.NameSuffix, item.NativeName, item.NameLocale, item.Email, item.Phone, string(item.AccountType), item.Locale, item.Timezone, nullable(item.OrgID), nullable(item.SupportOrgID), nullable(item.ManagerUserID), item.ReportingPath, item.WorkerNo, string(item.WorkerType), string(item.WorkStatus), nullable(item.StartDate), nullable(item.EndDate), string(item.Status), item.Version, item.CreatedAt, item.UpdatedAt)
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity user create: %w", err)
	}
	_, err = s.backend.DB().ExecContext(ctx, statement, arguments...)
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

func (s *Store) UpdateManyWithinDataScope(ctx context.Context, workspaceID string, items []identitymodel.IdentityUser, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if strings.TrimSpace(item.ID) == "" {
			return false, fmt.Errorf("user id is required")
		}
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	allowed, err := s.UpdateManyWithExecutorWithinDataScope(ctx, tx, workspaceID, items, scope)
	if err != nil || !allowed {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) UpdateManyWithExecutorWithinDataScope(ctx context.Context, tx *sql.Tx, workspaceID string, items []identitymodel.IdentityUser, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if strings.TrimSpace(item.ID) == "" {
			return false, fmt.Errorf("user id is required")
		}
	}
	ids := make([]string, len(items))
	for index := range items {
		ids[index] = items[index].ID
	}
	allowed, err := scopedUserMutationCandidatesExist(ctx, tx, s.backend.SQLRenderer(), workspaceID, ids, scope)
	if err != nil {
		return false, err
	}
	if !allowed {
		return false, nil
	}
	for _, item := range items {
		if item.Status == "" {
			item.Status = identitymodel.IdentityStatusActive
		}
		if item.AccountType == "" {
			item.AccountType = identitymodel.IdentityAccountHuman
		}
		predicates := []query.Predicate{query.Equal("id", item.ID)}
		if !scope.Unrestricted {
			predicates = append(predicates, userDataScopePredicate(scope))
		}
		builder := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).
			Set("name", item.Name).
			Set("given_name", item.GivenName).
			Set("middle_name", item.MiddleName).
			Set("family_name", item.FamilyName).
			Set("name_prefix", item.NamePrefix).
			Set("name_suffix", item.NameSuffix).
			Set("native_name", item.NativeName).
			Set("name_locale", item.NameLocale).
			Set("email", item.Email).
			Set("phone", item.Phone).
			Set("account_type", string(item.AccountType)).
			Set("locale", item.Locale).
			Set("timezone", item.Timezone).
			Set("org_id", nullable(item.OrgID)).
			Set("support_org_id", nullable(item.SupportOrgID)).
			Set("manager_user_id", nullable(item.ManagerUserID)).
			Set("reporting_path", item.ReportingPath).
			Set("worker_no", item.WorkerNo).
			Set("worker_type", string(item.WorkerType)).
			Set("work_status", string(item.WorkStatus)).
			Set("start_date", nullable(item.StartDate)).
			Set("end_date", nullable(item.EndDate)).
			Set("status", string(item.Status)).
			SetExpression("version", query.Add(query.Column("version"), query.Value(1))).
			Set("updated_at", s.now()).
			Where(query.And(predicates...))
		statement, arguments, buildErr := builder.Build()
		if buildErr != nil {
			return false, fmt.Errorf("build scoped identity user update: %w", buildErr)
		}
		result, executeErr := tx.ExecContext(ctx, statement, arguments...)
		if executeErr != nil {
			return false, executeErr
		}
		count, countErr := result.RowsAffected()
		if countErr != nil {
			return false, countErr
		}
		if count != 1 {
			return false, nil
		}
	}
	return true, nil
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

func (s *Store) RemoveWithinDataScope(ctx context.Context, workspaceID, userID string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return false, err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	predicates := []query.Predicate{query.Equal("id", userID)}
	if !scope.Unrestricted {
		predicates = append(predicates, userDataScopePredicate(scope))
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).Columns("id").Where(query.And(predicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build scoped identity user delete candidate query: %w", err)
	}
	var persistedID string
	if err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&persistedID); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	for _, table := range []string{"_identity_user_role_assignments", "_identity_credentials", "_identity_external_accounts", "_identity_mfa_factors", "_identity_auth_refresh_tokens"} {
		statement, arguments, buildErr := query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), table, workspaceID).Where(query.Equal("user_id", userID)).Build()
		if buildErr != nil {
			return false, fmt.Errorf("build identity user relation delete: %w", buildErr)
		}
		if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
			return false, err
		}
	}
	statement, arguments, err = query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).Where(query.And(predicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build identity user delete: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if count != 1 {
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
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

func (s *Store) SetStatusWithinDataScope(ctx context.Context, workspaceID, userID string, status identitymodel.IdentityStatus, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return false, err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	allowed, err := scopedUserMutationCandidatesExist(ctx, tx, s.backend.SQLRenderer(), workspaceID, []string{userID}, scope)
	if err != nil || !allowed {
		return false, err
	}
	predicates := []query.Predicate{query.Equal("id", userID)}
	if !scope.Unrestricted {
		predicates = append(predicates, userDataScopePredicate(scope))
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).Set("status", string(status)).SetExpression("version", query.Add(query.Column("version"), query.Value(1))).Set("updated_at", s.now()).Where(query.And(predicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build identity user status update: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) DisableWithinDataScope(ctx context.Context, workspaceID, userID string, scope identitymodel.IdentityDataScopeFilter) (int, bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return 0, false, err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	allowed, err := scopedUserMutationCandidatesExist(ctx, tx, s.backend.SQLRenderer(), workspaceID, []string{userID}, scope)
	if err != nil || !allowed {
		return 0, false, err
	}
	predicates := []query.Predicate{query.Equal("id", userID)}
	if !scope.Unrestricted {
		predicates = append(predicates, userDataScopePredicate(scope))
	}
	now := s.now()
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).
		Set("status", string(identitymodel.IdentityStatusDisabled)).
		SetExpression("version", query.Add(query.Column("version"), query.Value(1))).
		Set("updated_at", now).
		Where(query.And(predicates...)).
		Build()
	if err != nil {
		return 0, false, fmt.Errorf("build scoped identity account disable: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return 0, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return 0, false, err
	}
	if changed != 1 {
		return 0, false, nil
	}
	statement, arguments, err = query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
		Set("revoked_at", now).
		Set("updated_at", now).
		Where(query.And(query.Equal("user_id", userID), query.IsNull("revoked_at"))).
		Build()
	if err != nil {
		return 0, false, fmt.Errorf("build identity refresh-token revocation: %w", err)
	}
	revoked, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return 0, false, err
	}
	revokedCount, err := revoked.RowsAffected()
	if err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return int(revokedCount), true, nil
}

func selectUsers(renderer ormdialect.Renderer, workspaceID string) *query.SelectBuilder {
	return query.NewWorkspaceSelectBuilder(renderer, "_identity_users", workspaceID).Columns("id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "org_id", "support_org_id", "manager_user_id", "reporting_path", "worker_no", "worker_type", "work_status", "start_date", "end_date", "status", "version", "created_at", "updated_at")
}

func scopedUserMutationCandidatesExist(ctx context.Context, tx *sql.Tx, renderer ormdialect.Renderer, workspaceID string, userIDs []string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	if len(userIDs) == 0 {
		return true, nil
	}
	values := make([]any, 0, len(userIDs))
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		userID = strings.TrimSpace(userID)
		if userID == "" {
			return false, fmt.Errorf("user id is required")
		}
		if _, duplicate := seen[userID]; duplicate {
			return false, fmt.Errorf("duplicate user id %q", userID)
		}
		seen[userID] = struct{}{}
		values = append(values, userID)
	}
	predicates := []query.Predicate{query.In("id", values...)}
	if !scope.Unrestricted {
		predicates = append(predicates, userDataScopePredicate(scope))
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(renderer, "_identity_users", workspaceID).
		Columns("id").
		Where(query.And(predicates...)).
		Build()
	if err != nil {
		return false, fmt.Errorf("build scoped identity user mutation candidate query: %w", err)
	}
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	matched := 0
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return false, err
		}
		matched++
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return matched == len(userIDs), nil
}
func scan(scanner interface{ Scan(...any) error }) (identitymodel.IdentityUser, error) {
	var item identitymodel.IdentityUser
	var accountType, workerType, workStatus, status string
	var organizationUnitID, supportOrganizationUnitID, managerUserID, startDate, endDate sql.NullString
	err := scanner.Scan(&item.ID, &item.Name, &item.GivenName, &item.MiddleName, &item.FamilyName, &item.NamePrefix, &item.NameSuffix, &item.NativeName, &item.NameLocale, &item.Email, &item.Phone, &accountType, &item.Locale, &item.Timezone, &organizationUnitID, &supportOrganizationUnitID, &managerUserID, &item.ReportingPath, &item.WorkerNo, &workerType, &workStatus, &startDate, &endDate, &status, &item.Version, &item.CreatedAt, &item.UpdatedAt)
	item.AccountType, item.Status = identitymodel.IdentityAccountType(accountType), identitymodel.IdentityStatus(status)
	item.OrgID = organizationUnitID.String
	item.SupportOrgID = supportOrganizationUnitID.String
	item.ManagerUserID = managerUserID.String
	item.WorkerType, item.WorkStatus = identitymodel.IdentityWorkerType(workerType), identitymodel.IdentityWorkStatus(workStatus)
	item.StartDate, item.EndDate = startDate.String, endDate.String
	return item, err
}

func nullable(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
func workspace(value string) (string, error) {
	id, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
