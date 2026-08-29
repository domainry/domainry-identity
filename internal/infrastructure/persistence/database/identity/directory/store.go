package directory

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/pagination"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
}

type Store struct{ backend Backend }

func New(backend Backend) Store { return Store{backend: backend} }

var identityUserDirectoryColumns = map[string]string{
	"id": "id", "name": "name", "given_name": "given_name", "middle_name": "middle_name", "family_name": "family_name",
	"name_prefix": "name_prefix", "name_suffix": "name_suffix", "native_name": "native_name", "name_locale": "name_locale",
	"email": "email", "phone": "phone", "account_type": "account_type", "locale": "locale", "timezone": "timezone", "status": "status",
}

var identityWorkforceDirectoryColumns = map[string]string{
	"id": "id", "organization_id": "organization_id", "identity_user_id": "identity_user_id", "worker_no": "worker_no",
	"worker_type": "worker_type", "work_status": "work_status", "start_date": "start_date", "end_date": "end_date",
}

func (s Store) SearchIdentityUsers(ctx context.Context, workspaceID string, query identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	conditions := identityDirectoryPredicates(query, identityUserDirectoryColumns)
	total, err := s.identityDirectoryCount(ctx, workspaceID, "identity_users", conditions)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	columns := []string{
		"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at",
	}
	statement, args, err := s.PageSQL(ctx, workspaceID, "identity_users", columns, query, conditions)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	rows, err := s.backend.DB().QueryContext(ctx, statement, args...)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	defer rows.Close()
	cursor := identitySQLDirectoryCursor(query)
	items := make([]identitymodel.IdentityUser, 0, cursor.FetchLimit())
	for rows.Next() {
		var user identitymodel.IdentityUser
		var accountType, status string
		if err := rows.Scan(
			&user.ID, &user.Name, &user.GivenName, &user.MiddleName, &user.FamilyName, &user.NamePrefix, &user.NameSuffix, &user.NativeName, &user.NameLocale,
			&user.Email, &user.Phone, &accountType, &user.Locale, &user.Timezone, &status, &user.Version, &user.CreatedAt, &user.UpdatedAt,
		); err != nil {
			return identitymodel.IdentityUserPage{}, err
		}
		user.AccountType = identitymodel.IdentityAccountType(accountType)
		user.Status = identitymodel.IdentityStatus(status)
		items = append(items, user)
	}
	if err := rows.Err(); err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	page := pagination.Boundary(cursor, items, func(user identitymodel.IdentityUser) string { return user.ID })
	return identitymodel.IdentityUserPage{Items: page.Items, PageSize: cursor.PageSize(), Total: total, HasNext: page.HasNext, NextID: page.NextID}, nil
}

func (s Store) SearchIdentityWorkforceProfiles(ctx context.Context, workspaceID string, query identitymodel.IdentityListQuery) (identitymodel.IdentityWorkforceProfilePage, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	conditions := identityDirectoryPredicates(query, identityWorkforceDirectoryColumns)
	total, err := s.identityDirectoryCount(ctx, workspaceID, "identity_workforce_profiles", conditions)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	columns := []string{"id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version"}
	statement, args, err := s.PageSQL(ctx, workspaceID, "identity_workforce_profiles", columns, query, conditions)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	rows, err := s.backend.DB().QueryContext(ctx, statement, args...)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	defer rows.Close()
	cursor := identitySQLDirectoryCursor(query)
	items := make([]identitymodel.IdentityWorkforceProfile, 0, cursor.FetchLimit())
	for rows.Next() {
		profile, scanErr := scanIdentityWorkforceProfile(rows)
		if scanErr != nil {
			return identitymodel.IdentityWorkforceProfilePage{}, scanErr
		}
		items = append(items, profile)
	}
	if err := rows.Err(); err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	page := pagination.Boundary(cursor, items, func(profile identitymodel.IdentityWorkforceProfile) string { return profile.ID })
	return identitymodel.IdentityWorkforceProfilePage{Items: page.Items, PageSize: cursor.PageSize(), Total: total, HasNext: page.HasNext, NextID: page.NextID}, nil
}

func identityDirectoryPredicates(query identitymodel.IdentityListQuery, columns map[string]string) []ormbuilder.Predicate {
	conditions := make([]ormbuilder.Predicate, 0, len(query.SearchFields)+len(query.Filters))
	if needle := strings.ToLower(strings.TrimSpace(query.Search)); needle != "" {
		search := make([]ormbuilder.Predicate, 0, len(query.SearchFields))
		for _, field := range query.SearchFields {
			search = append(search, ormbuilder.LikeValue(
				ormbuilder.Lower(ormbuilder.Coalesce(ormbuilder.Column(columns[field]), ormbuilder.Value(""))), "%"+needle+"%",
			))
		}
		conditions = append(conditions, ormbuilder.Or(search...))
	}
	for _, field := range sortedStringKeys(query.Filters) {
		conditions = append(conditions, ormbuilder.EqualValue(
			ormbuilder.Lower(ormbuilder.Coalesce(ormbuilder.Column(columns[field]), ormbuilder.Value(""))),
			strings.ToLower(strings.TrimSpace(fmt.Sprint(query.Filters[field]))),
		))
	}
	return conditions
}

func Predicates(query identitymodel.IdentityListQuery, columns map[string]string) []ormbuilder.Predicate {
	return identityDirectoryPredicates(query, columns)
}

func (s Store) identityDirectoryCount(ctx context.Context, workspaceID, table string, conditions []ormbuilder.Predicate) (int, error) {
	builder := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), table, workspaceID).
		Projections(ormbuilder.Project(ormbuilder.CountAll()))
	applyIdentityDirectoryPredicates(builder, conditions)
	query, args, err := builder.Build()
	if err != nil {
		return 0, err
	}
	var total int
	err = s.backend.DB().QueryRowContext(ctx, query, args...).Scan(&total)
	return total, err
}

func (s Store) PageSQL(ctx context.Context, workspaceID, table string, columns []string, query identitymodel.IdentityListQuery, conditions []ormbuilder.Predicate) (string, []any, error) {
	orders := identityDirectoryKeysetOrders(query.Sort)
	builder := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), table, workspaceID).
		Columns(columns...)
	applyIdentityDirectoryPredicates(builder, conditions)
	cursor := identitySQLDirectoryCursor(query)
	if strings.TrimSpace(query.AfterID) == "" {
		return builder.FirstPage(cursor.FetchLimit(), orders...).Build()
	}
	values, err := s.identityDirectoryCursorValues(ctx, workspaceID, table, query.AfterID, query.Sort, conditions)
	if err != nil {
		return "", nil, err
	}
	return builder.NextPage(cursor.AfterID(), cursor.FetchLimit(), values, orders...).Build()
}

func (s Store) identityDirectoryCursorValues(ctx context.Context, workspaceID, table, afterID string, rules []identitymodel.IdentitySortRule, conditions []ormbuilder.Predicate) (map[string]any, error) {
	columns := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Field != "id" {
			columns = append(columns, rule.Field)
		}
	}
	if len(columns) == 0 {
		return map[string]any{}, nil
	}
	predicates := append([]ormbuilder.Predicate(nil), conditions...)
	predicates = append(predicates, ormbuilder.Equal("id", strings.TrimSpace(afterID)))
	statement, args, err := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), table, workspaceID).
		Columns(columns...).Where(ormbuilder.And(predicates...)).Limit(1).Build()
	if err != nil {
		return nil, err
	}
	values := make([]any, len(columns))
	destinations := make([]any, len(columns))
	for index := range values {
		destinations[index] = &values[index]
	}
	if err := s.backend.DB().QueryRowContext(ctx, statement, args...).Scan(destinations...); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("identity directory cursor %q is not in the workspace result", afterID)
		}
		return nil, err
	}
	result := make(map[string]any, len(columns))
	for index, column := range columns {
		result[column] = values[index]
	}
	return result, nil
}

func applyIdentityDirectoryPredicates(builder *ormbuilder.SelectBuilder, conditions []ormbuilder.Predicate) {
	if len(conditions) > 0 {
		builder.Where(ormbuilder.And(conditions...))
	}
}

func identityDirectoryKeysetOrders(rules []identitymodel.IdentitySortRule) []ormbuilder.KeysetOrder {
	orders := make([]ormbuilder.KeysetOrder, 0, len(rules))
	for _, rule := range rules {
		if strings.EqualFold(rule.Direction, "desc") {
			orders = append(orders, ormbuilder.KeysetDescending(rule.Field))
		} else {
			orders = append(orders, ormbuilder.KeysetAscending(rule.Field))
		}
	}
	return orders
}

func identitySQLDirectoryCursor(query identitymodel.IdentityListQuery) pagination.Cursor {
	return pagination.NewCursor(query.AfterID, query.PageSize, pagination.CursorOptions{DefaultPageSize: 20, MaximumPageSize: 200})
}

func sortedStringKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func SortedStringKeys(values map[string]any) []string { return sortedStringKeys(values) }

func identityWorkspaceID(value string) (string, error) {
	workspace, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return workspace.String(), nil
}

type workforceProfileScanner interface{ Scan(...any) error }

func scanIdentityWorkforceProfile(scanner workforceProfileScanner) (identitymodel.IdentityWorkforceProfile, error) {
	var profile identitymodel.IdentityWorkforceProfile
	var workerType, workStatus string
	var startDate, endDate, primaryAssignmentID sql.NullString
	err := scanner.Scan(&profile.ID, &profile.OrganizationID, &profile.IdentityUserID, &profile.WorkerNo, &workerType, &workStatus, &startDate, &endDate, &primaryAssignmentID, &profile.Version)
	profile.WorkerType = identitymodel.IdentityWorkerType(workerType)
	profile.WorkStatus = identitymodel.IdentityWorkStatus(workStatus)
	profile.StartDate, profile.EndDate, profile.PrimaryAssignmentID = startDate.String, endDate.String, primaryAssignmentID.String
	return profile, err
}
