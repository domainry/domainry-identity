package directory

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/pagination"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	MaxParameters() int
	QueryIdentityContext(context.Context, string, ...any) (*sql.Rows, error)
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

func (s Store) SearchIdentityUsers(ctx context.Context, workspaceID string, queryValue identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	conditions := identityDirectoryPredicates(queryValue, identityUserDirectoryColumns)
	total, err := s.identityDirectoryCount(ctx, workspaceID, "_identity_users", conditions)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	columns := []string{
		"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at",
	}
	statement, args, err := s.PageSQL(ctx, workspaceID, "_identity_users", columns, queryValue, conditions)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	rows, err := s.backend.DB().QueryContext(ctx, statement, args...)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	defer rows.Close()
	cursor := identitySQLDirectoryCursor(queryValue)
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

func (s Store) SearchIdentityWorkforceProfiles(ctx context.Context, workspaceID string, queryValue identitymodel.IdentityListQuery) (identitymodel.IdentityWorkforceProfilePage, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	conditions := identityDirectoryPredicates(queryValue, identityWorkforceDirectoryColumns)
	total, err := s.identityDirectoryCount(ctx, workspaceID, "_identity_workforce_profiles", conditions)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	columns := []string{"id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version"}
	statement, args, err := s.PageSQL(ctx, workspaceID, "_identity_workforce_profiles", columns, queryValue, conditions)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	rows, err := s.backend.DB().QueryContext(ctx, statement, args...)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	defer rows.Close()
	cursor := identitySQLDirectoryCursor(queryValue)
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

func identityDirectoryPredicates(queryValue identitymodel.IdentityListQuery, columns map[string]string) []query.Predicate {
	conditions := make([]query.Predicate, 0, len(queryValue.SearchFields)+len(queryValue.Filters))
	if needle := strings.ToLower(strings.TrimSpace(queryValue.Search)); needle != "" {
		search := make([]query.Predicate, 0, len(queryValue.SearchFields))
		for _, field := range queryValue.SearchFields {
			search = append(search, query.LikeValue(
				query.Lower(query.Coalesce(query.Column(columns[field]), query.Value(""))), "%"+needle+"%",
			))
		}
		conditions = append(conditions, query.Or(search...))
	}
	for _, field := range sortedStringKeys(queryValue.Filters) {
		conditions = append(conditions, query.EqualValue(
			query.Lower(query.Coalesce(query.Column(columns[field]), query.Value(""))),
			strings.ToLower(strings.TrimSpace(fmt.Sprint(queryValue.Filters[field]))),
		))
	}
	return conditions
}

func Predicates(queryValue identitymodel.IdentityListQuery, columns map[string]string) []query.Predicate {
	return identityDirectoryPredicates(queryValue, columns)
}

func (s Store) identityDirectoryCount(ctx context.Context, workspaceID, table string, conditions []query.Predicate) (int, error) {
	builder := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), table, workspaceID).
		Projections(query.Project(query.CountAll()))
	applyIdentityDirectoryPredicates(builder, conditions)
	queryValue, args, err := builder.Build()
	if err != nil {
		return 0, err
	}
	var total int
	err = s.backend.DB().QueryRowContext(ctx, queryValue, args...).Scan(&total)
	return total, err
}

func (s Store) PageSQL(ctx context.Context, workspaceID, table string, columns []string, queryValue identitymodel.IdentityListQuery, conditions []query.Predicate) (string, []any, error) {
	orders := identityDirectoryKeysetOrders(queryValue.Sort)
	builder := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), table, workspaceID).
		Columns(columns...)
	applyIdentityDirectoryPredicates(builder, conditions)
	cursor := identitySQLDirectoryCursor(queryValue)
	if strings.TrimSpace(queryValue.AfterID) == "" {
		return builder.FirstPage(cursor.FetchLimit(), orders...).Build()
	}
	values, err := s.identityDirectoryCursorValues(ctx, workspaceID, table, queryValue.AfterID, queryValue.Sort, conditions)
	if err != nil {
		return "", nil, err
	}
	return builder.NextPage(cursor.AfterID(), cursor.FetchLimit(), values, orders...).Build()
}

func (s Store) identityDirectoryCursorValues(ctx context.Context, workspaceID, table, afterID string, rules []identitymodel.IdentitySortRule, conditions []query.Predicate) (map[string]any, error) {
	columns := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Field != "id" {
			columns = append(columns, rule.Field)
		}
	}
	if len(columns) == 0 {
		return map[string]any{}, nil
	}
	predicates := append([]query.Predicate(nil), conditions...)
	predicates = append(predicates, query.Equal("id", strings.TrimSpace(afterID)))
	statement, args, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), table, workspaceID).
		Columns(columns...).Where(query.And(predicates...)).Limit(1).Build()
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

func applyIdentityDirectoryPredicates(builder *query.SelectBuilder, conditions []query.Predicate) {
	if len(conditions) > 0 {
		builder.Where(query.And(conditions...))
	}
}

func identityDirectoryKeysetOrders(rules []identitymodel.IdentitySortRule) []query.KeysetOrder {
	orders := make([]query.KeysetOrder, 0, len(rules))
	for _, rule := range rules {
		if strings.EqualFold(rule.Direction, "desc") {
			orders = append(orders, query.KeysetDescending(rule.Field))
		} else {
			orders = append(orders, query.KeysetAscending(rule.Field))
		}
	}
	return orders
}

func identitySQLDirectoryCursor(queryValue identitymodel.IdentityListQuery) pagination.Cursor {
	return pagination.NewCursor(queryValue.AfterID, queryValue.PageSize, pagination.CursorOptions{DefaultPageSize: 20, MaximumPageSize: 200})
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
