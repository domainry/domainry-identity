package identity

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

var identityUserDirectoryColumns = map[string]string{
	"id": "id", "name": "name", "given_name": "given_name", "middle_name": "middle_name", "family_name": "family_name",
	"name_prefix": "name_prefix", "name_suffix": "name_suffix", "native_name": "native_name", "name_locale": "name_locale",
	"email": "email", "phone": "phone", "account_type": "account_type", "locale": "locale", "timezone": "timezone", "status": "status",
}

var identityWorkforceDirectoryColumns = map[string]string{
	"id": "id", "organization_id": "organization_id", "identity_user_id": "identity_user_id", "worker_no": "worker_no",
	"worker_type": "worker_type", "work_status": "work_status", "start_date": "start_date", "end_date": "end_date",
}

func (s *SQLIdentityStore) SearchIdentityUsers(ctx context.Context, workspaceID string, query identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
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
	statement, args, err := s.identityDirectoryPageSQL(ctx, workspaceID, "identity_users", columns, query, conditions)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	defer rows.Close()
	items := make([]identitymodel.IdentityUser, 0, query.PageSize+1)
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
	items, hasNext, nextID := identityUserPageBoundary(items, query.PageSize)
	return identitymodel.IdentityUserPage{Items: items, PageSize: query.PageSize, Total: total, HasNext: hasNext, NextID: nextID}, nil
}

func (s *SQLIdentityStore) SearchIdentityWorkforceProfiles(ctx context.Context, workspaceID string, query identitymodel.IdentityListQuery) (identitymodel.IdentityWorkforceProfilePage, error) {
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
	statement, args, err := s.identityDirectoryPageSQL(ctx, workspaceID, "identity_workforce_profiles", columns, query, conditions)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	defer rows.Close()
	items := make([]identitymodel.IdentityWorkforceProfile, 0, query.PageSize+1)
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
	items, hasNext, nextID := identityWorkforcePageBoundary(items, query.PageSize)
	return identitymodel.IdentityWorkforceProfilePage{Items: items, PageSize: query.PageSize, Total: total, HasNext: hasNext, NextID: nextID}, nil
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

func (s *SQLIdentityStore) identityDirectoryCount(ctx context.Context, workspaceID, table string, conditions []ormbuilder.Predicate) (int, error) {
	builder := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), table, workspaceID).
		Projections(ormbuilder.Project(ormbuilder.CountAll()))
	applyIdentityDirectoryPredicates(builder, conditions)
	query, args, err := builder.Build()
	if err != nil {
		return 0, err
	}
	var total int
	err = s.db.QueryRowContext(ctx, query, args...).Scan(&total)
	return total, err
}

func (s *SQLIdentityStore) identityDirectoryPageSQL(ctx context.Context, workspaceID, table string, columns []string, query identitymodel.IdentityListQuery, conditions []ormbuilder.Predicate) (string, []any, error) {
	orders := identityDirectoryKeysetOrders(query.Sort)
	builder := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), table, workspaceID).
		Columns(columns...)
	applyIdentityDirectoryPredicates(builder, conditions)
	limit := query.PageSize + 1
	if strings.TrimSpace(query.AfterID) == "" {
		return builder.FirstPage(limit, orders...).Build()
	}
	values, err := s.identityDirectoryCursorValues(ctx, workspaceID, table, query.AfterID, query.Sort, conditions)
	if err != nil {
		return "", nil, err
	}
	return builder.NextPage(query.AfterID, limit, values, orders...).Build()
}

func (s *SQLIdentityStore) identityDirectoryCursorValues(ctx context.Context, workspaceID, table, afterID string, rules []identitymodel.IdentitySortRule, conditions []ormbuilder.Predicate) (map[string]any, error) {
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
	statement, args, err := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), table, workspaceID).
		Columns(columns...).Where(ormbuilder.And(predicates...)).Limit(1).Build()
	if err != nil {
		return nil, err
	}
	values := make([]any, len(columns))
	destinations := make([]any, len(columns))
	for index := range values {
		destinations[index] = &values[index]
	}
	if err := s.db.QueryRowContext(ctx, statement, args...).Scan(destinations...); err != nil {
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

func identityUserPageBoundary(items []identitymodel.IdentityUser, pageSize int) ([]identitymodel.IdentityUser, bool, string) {
	if len(items) <= pageSize {
		return items, false, ""
	}
	items = items[:pageSize]
	return items, true, items[len(items)-1].ID
}

func identityWorkforcePageBoundary(items []identitymodel.IdentityWorkforceProfile, pageSize int) ([]identitymodel.IdentityWorkforceProfile, bool, string) {
	if len(items) <= pageSize {
		return items, false, ""
	}
	items = items[:pageSize]
	return items, true, items[len(items)-1].ID
}

func sortedStringKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
