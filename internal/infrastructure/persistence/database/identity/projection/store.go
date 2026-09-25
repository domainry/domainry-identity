package projection

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/pagination"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
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

var identityUserProjectionColumns = map[string]string{
	"id": "id", "name": "name", "given_name": "given_name", "middle_name": "middle_name", "family_name": "family_name",
	"name_prefix": "name_prefix", "name_suffix": "name_suffix", "native_name": "native_name", "name_locale": "name_locale",
	"email": "email", "phone": "phone", "account_type": "account_type", "locale": "locale", "timezone": "timezone",
	"org_id": "org_id", "support_org_id": "support_org_id", "manager_user_id": "manager_user_id", "reporting_path": "reporting_path", "worker_no": "worker_no", "worker_type": "worker_type", "work_status": "work_status",
	"start_date": "start_date", "end_date": "end_date", "status": "status",
}

func (s Store) SearchIdentityUsers(ctx context.Context, workspaceID string, queryValue identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
	return s.SearchIdentityUsersWithinDataScope(ctx, workspaceID, queryValue, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s Store) SearchIdentityUsersWithinDataScope(ctx context.Context, workspaceID string, queryValue identitymodel.IdentityListQuery, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityUserPage, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	conditions := identityProjectionPredicates(queryValue, identityUserProjectionColumns)
	if !scope.Unrestricted {
		conditions = append(conditions, identityUserDataScopePredicate(scope))
	}
	total, err := s.identityProjectionCount(ctx, workspaceID, "_identity_users", conditions)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	columns := []string{
		"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "org_id", "support_org_id", "manager_user_id", "reporting_path", "worker_no", "worker_type", "work_status", "start_date", "end_date", "status", "version", "created_at", "updated_at",
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
	cursor := identitySQLProjectionCursor(queryValue)
	items := make([]identitymodel.IdentityUser, 0, cursor.FetchLimit())
	for rows.Next() {
		var user identitymodel.IdentityUser
		var accountType, workerType, workStatus, status string
		var organizationUnitID, supportOrganizationUnitID, managerUserID, startDate, endDate sql.NullString
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&user.ID, &user.Name, &user.GivenName, &user.MiddleName, &user.FamilyName, &user.NamePrefix, &user.NameSuffix, &user.NativeName, &user.NameLocale,
			&user.Email, &user.Phone, &accountType, &user.Locale, &user.Timezone, &organizationUnitID, &supportOrganizationUnitID, &managerUserID, &user.ReportingPath, &user.WorkerNo, &workerType, &workStatus, &startDate, &endDate, &status, &user.Version, &createdAt, &updatedAt,
		); err != nil {
			return identitymodel.IdentityUserPage{}, err
		}
		user.AccountType = identitymodel.IdentityAccountType(accountType)
		user.OrgID = organizationUnitID.String
		user.SupportOrgID = supportOrganizationUnitID.String
		user.ManagerUserID = managerUserID.String
		user.WorkerType, user.WorkStatus = identitymodel.IdentityWorkerType(workerType), identitymodel.IdentityWorkStatus(workStatus)
		user.StartDate, user.EndDate = startDate.String, endDate.String
		user.Status = identitymodel.IdentityStatus(status)
		user.CreatedAt, user.UpdatedAt = timevalue.String(createdAt), timevalue.String(updatedAt)
		items = append(items, user)
	}
	if err := rows.Err(); err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	page := pagination.Boundary(cursor, items, func(user identitymodel.IdentityUser) string { return user.ID })
	return identitymodel.IdentityUserPage{Items: page.Items, PageSize: cursor.PageSize(), Total: total, HasNext: page.HasNext, NextID: page.NextID}, nil
}

func identityUserDataScopePredicate(scope identitymodel.IdentityDataScopeFilter) query.Predicate {
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

func identityProjectionPredicates(queryValue identitymodel.IdentityListQuery, columns map[string]string) []query.Predicate {
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
	return identityProjectionPredicates(queryValue, columns)
}

func (s Store) identityProjectionCount(ctx context.Context, workspaceID, table string, conditions []query.Predicate) (int, error) {
	builder := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), table, workspaceID).
		Projections(query.Project(query.CountAll()))
	applyIdentityProjectionPredicates(builder, conditions)
	queryValue, args, err := builder.Build()
	if err != nil {
		return 0, err
	}
	var total int
	err = s.backend.DB().QueryRowContext(ctx, queryValue, args...).Scan(&total)
	return total, err
}

func (s Store) PageSQL(ctx context.Context, workspaceID, table string, columns []string, queryValue identitymodel.IdentityListQuery, conditions []query.Predicate) (string, []any, error) {
	orders := identityProjectionKeysetOrders(queryValue.Sort)
	builder := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), table, workspaceID).
		Columns(columns...)
	applyIdentityProjectionPredicates(builder, conditions)
	cursor := identitySQLProjectionCursor(queryValue)
	if strings.TrimSpace(queryValue.AfterID) == "" {
		return builder.FirstPage(cursor.FetchLimit(), orders...).Build()
	}
	values, err := s.identityProjectionCursorValues(ctx, workspaceID, table, queryValue.AfterID, queryValue.Sort, conditions)
	if err != nil {
		return "", nil, err
	}
	return builder.NextPage(cursor.AfterID(), cursor.FetchLimit(), values, orders...).Build()
}

func (s Store) identityProjectionCursorValues(ctx context.Context, workspaceID, table, afterID string, rules []identitymodel.IdentitySortRule, conditions []query.Predicate) (map[string]any, error) {
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
			return nil, fmt.Errorf("identity projection cursor %q is not in the workspace result", afterID)
		}
		return nil, err
	}
	result := make(map[string]any, len(columns))
	for index, column := range columns {
		result[column] = values[index]
	}
	return result, nil
}

func applyIdentityProjectionPredicates(builder *query.SelectBuilder, conditions []query.Predicate) {
	if len(conditions) > 0 {
		builder.Where(query.And(conditions...))
	}
}

func identityProjectionKeysetOrders(rules []identitymodel.IdentitySortRule) []query.KeysetOrder {
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

func identitySQLProjectionCursor(queryValue identitymodel.IdentityListQuery) pagination.Cursor {
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
