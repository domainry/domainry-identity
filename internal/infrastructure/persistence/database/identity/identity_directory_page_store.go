package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *SQLIdentityStore) SearchIdentityUsers(ctx context.Context, workspaceID string, query identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	where, args := s.identityDirectoryWhere(workspaceID, query, map[string]string{
		"id": "id", "name": "name", "given_name": "given_name", "middle_name": "middle_name", "family_name": "family_name",
		"name_prefix": "name_prefix", "name_suffix": "name_suffix", "native_name": "native_name", "name_locale": "name_locale",
		"email": "email", "phone": "phone", "account_type": "account_type", "locale": "locale", "timezone": "timezone", "status": "status",
	})
	total, err := s.identityDirectoryCount(ctx, "identity_users", where, args)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	order := s.identityDirectoryOrder(query.Sort, map[string]string{
		"id": "id", "name": "name", "given_name": "given_name", "middle_name": "middle_name", "family_name": "family_name",
		"name_prefix": "name_prefix", "name_suffix": "name_suffix", "native_name": "native_name", "name_locale": "name_locale",
		"email": "email", "phone": "phone", "account_type": "account_type", "locale": "locale", "timezone": "timezone", "status": "status",
	})
	page, pageSize := query.Page, query.PageSize
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, "SELECT "+s.identityColumns(
		"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at",
	)+
		" FROM "+s.tableIdentifier("identity_users")+where+order+
		" LIMIT "+s.placeholder(len(args)-1)+" OFFSET "+s.placeholder(len(args)), args...)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	defer rows.Close()
	items := make([]identitymodel.IdentityUser, 0, pageSize)
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
	return identitymodel.IdentityUserPage{Items: items, Page: page, PageSize: pageSize, Total: total, HasNext: page*pageSize < total}, nil
}

func (s *SQLIdentityStore) SearchIdentityWorkforceProfiles(ctx context.Context, workspaceID string, query identitymodel.IdentityListQuery) (identitymodel.IdentityWorkforceProfilePage, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	columns := map[string]string{
		"id": "id", "organization_id": "organization_id", "identity_user_id": "identity_user_id", "worker_no": "worker_no",
		"worker_type": "worker_type", "work_status": "work_status", "start_date": "start_date", "end_date": "end_date",
	}
	where, args := s.identityDirectoryWhere(workspaceID, query, columns)
	total, err := s.identityDirectoryCount(ctx, "identity_workforce_profiles", where, args)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	order := s.identityDirectoryOrder(query.Sort, columns)
	page, pageSize := query.Page, query.PageSize
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, "SELECT "+s.identityColumns("id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version")+
		" FROM "+s.tableIdentifier("identity_workforce_profiles")+where+order+
		" LIMIT "+s.placeholder(len(args)-1)+" OFFSET "+s.placeholder(len(args)), args...)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	defer rows.Close()
	items := make([]identitymodel.IdentityWorkforceProfile, 0, pageSize)
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
	return identitymodel.IdentityWorkforceProfilePage{Items: items, Page: page, PageSize: pageSize, Total: total, HasNext: page*pageSize < total}, nil
}

func (s *SQLIdentityStore) identityDirectoryWhere(workspaceID string, query identitymodel.IdentityListQuery, columns map[string]string) (string, []any) {
	args := []any{workspaceID}
	clauses := []string{s.identifier("workspace_id") + " = " + s.placeholder(1)}
	if needle := strings.ToLower(strings.TrimSpace(query.Search)); needle != "" {
		search := make([]string, 0, len(query.SearchFields))
		for _, field := range query.SearchFields {
			column := columns[field]
			args = append(args, "%"+needle+"%")
			search = append(search, "LOWER(COALESCE("+s.identifier(column)+", '')) LIKE "+s.placeholder(len(args)))
		}
		clauses = append(clauses, "("+strings.Join(search, " OR ")+")")
	}
	for _, field := range sortedStringKeys(query.Filters) {
		args = append(args, strings.ToLower(strings.TrimSpace(fmt.Sprint(query.Filters[field]))))
		clauses = append(clauses, "LOWER(COALESCE("+s.identifier(columns[field])+", '')) = "+s.placeholder(len(args)))
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (s *SQLIdentityStore) identityDirectoryOrder(rules []identitymodel.IdentitySortRule, columns map[string]string) string {
	parts := make([]string, 0, len(rules))
	for _, rule := range rules {
		parts = append(parts, s.identifier(columns[rule.Field])+" "+strings.ToUpper(rule.Direction))
	}
	return " ORDER BY " + strings.Join(parts, ", ")
}

func (s *SQLIdentityStore) identityDirectoryCount(ctx context.Context, table, where string, args []any) (int, error) {
	var total int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.tableIdentifier(table)+where, args...).Scan(&total)
	return total, err
}

func sortedStringKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
