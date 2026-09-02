package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/pagination"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const identityDirectoryMaximumPageSize = 200

func identityDirectoryPagination(query identitymodel.IdentityListQuery) pagination.Cursor {
	return pagination.NewCursor(query.AfterID, query.PageSize, pagination.CursorOptions{
		DefaultPageSize: 20,
		MaximumPageSize: identityDirectoryMaximumPageSize,
	})
}

func identityDirectoryPage[T any](cursor pagination.Cursor, items []T, itemID func(T) string) (pagination.Page[T], error) {
	page, err := pagination.Slice(cursor, items, itemID)
	if err == nil {
		return page, nil
	}
	var cursorNotFound pagination.CursorNotFoundError
	if errors.As(err, &cursorNotFound) {
		return pagination.Page[T]{}, badRequest("backend.identity.directory_cursor_invalid", "after_id", cursorNotFound.AfterID)
	}
	return pagination.Page[T]{}, err
}

func identityDirectoryFields(requested, defaults []string, allowed map[string]bool, errorCode string) ([]string, error) {
	fields := requested
	if len(fields) == 0 {
		fields = defaults
	}
	for _, field := range fields {
		if !allowed[field] {
			return nil, badRequest(errorCode, "field", field)
		}
	}
	return fields, nil
}

func identityDirectoryFilters(filters map[string]any, allowed map[string]bool, errorCode string) (map[string]string, error) {
	normalized := make(map[string]string, len(filters))
	for field, value := range filters {
		if !allowed[field] {
			return nil, badRequest(errorCode, "field", field)
		}
		normalized[field] = strings.TrimSpace(fmt.Sprint(value))
	}
	return normalized, nil
}

func identityDirectorySort(query identitymodel.IdentityListQuery, defaultSort []identitymodel.IdentitySortRule, allowed map[string]bool, errorCode string) ([]identitymodel.IdentitySortRule, error) {
	rules := query.Sort
	if len(rules) == 0 {
		rules = defaultSort
	}
	for index := range rules {
		rules[index].Field = strings.TrimSpace(rules[index].Field)
		rules[index].Direction = strings.ToLower(strings.TrimSpace(rules[index].Direction))
		if !allowed[rules[index].Field] {
			return nil, badRequest(errorCode, "field", rules[index].Field)
		}
		if rules[index].Direction != "asc" && rules[index].Direction != "desc" {
			return nil, badRequest(errorCode, "direction", rules[index].Direction)
		}
	}
	return rules, nil
}

func identityDirectoryMatchesSearch(needle string, fields []string, value func(string) string) bool {
	if needle == "" {
		return true
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(value(field)), needle) {
			return true
		}
	}
	return false
}

func identityDirectoryMatchesFilters(filters map[string]string, value func(string) string) bool {
	for field, expected := range filters {
		if !strings.EqualFold(strings.TrimSpace(value(field)), expected) {
			return false
		}
	}
	return true
}

func identityDirectoryLess(rules []identitymodel.IdentitySortRule, left, right func(string) string) bool {
	for _, rule := range rules {
		comparison := strings.Compare(strings.ToLower(left(rule.Field)), strings.ToLower(right(rule.Field)))
		if comparison == 0 {
			continue
		}
		if rule.Direction == "desc" {
			return comparison > 0
		}
		return comparison < 0
	}
	return false
}

func identityUserValue(user identitymodel.IdentityUser, field string) string {
	switch field {
	case "id":
		return user.ID
	case "name":
		return user.Name
	case "given_name":
		return user.GivenName
	case "middle_name":
		return user.MiddleName
	case "family_name":
		return user.FamilyName
	case "name_prefix":
		return user.NamePrefix
	case "name_suffix":
		return user.NameSuffix
	case "native_name":
		return user.NativeName
	case "name_locale":
		return user.NameLocale
	case "account_type":
		return string(user.AccountType)
	case "locale":
		return user.Locale
	case "timezone":
		return user.Timezone
	case "org_id":
		return user.OrgID
	case "worker_no":
		return user.WorkerNo
	case "worker_type":
		return string(user.WorkerType)
	case "work_status":
		return string(user.WorkStatus)
	case "start_date":
		return user.StartDate
	case "end_date":
		return user.EndDate
	case "email":
		return user.Email
	case "phone":
		return user.Phone
	case "status":
		return string(user.Status)
	default:
		return ""
	}
}

func (s *IdentityDomainService) SearchUsers(ctx context.Context, query identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
	allowed := map[string]bool{
		"id": true, "name": true, "given_name": true, "middle_name": true, "family_name": true,
		"name_prefix": true, "name_suffix": true, "native_name": true, "name_locale": true,
		"account_type": true, "locale": true, "timezone": true, "org_id": true,
		"worker_no": true, "worker_type": true, "work_status": true, "start_date": true, "end_date": true,
		"email": true, "phone": true, "status": true,
	}
	fields, err := identityDirectoryFields(query.SearchFields, []string{"name", "given_name", "middle_name", "family_name", "native_name", "email", "phone", "worker_no"}, allowed, "backend.identity.user_search_field_invalid")
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	filters, err := identityDirectoryFilters(query.Filters, allowed, "backend.identity.user_filter_field_invalid")
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	rules, err := identityDirectorySort(query, []identitymodel.IdentitySortRule{{Field: "name", Direction: "asc"}, {Field: "id", Direction: "asc"}}, allowed, "backend.identity.user_sort_invalid")
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	cursor := identityDirectoryPagination(query)
	query.PageSize, query.SearchFields, query.Filters, query.Sort = cursor.PageSize(), fields, mapStringAny(filters), rules
	if repository, ok := s.repo.(interface {
		SearchIdentityUsers(context.Context, string, identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error)
	}); ok {
		return repository.SearchIdentityUsers(ctx, s.workspace, query)
	}
	users, err := s.repo.ListIdentityUsers(ctx, s.workspace)
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	needle := strings.ToLower(strings.TrimSpace(query.Search))
	filtered := make([]identitymodel.IdentityUser, 0, len(users))
	for _, user := range users {
		value := func(field string) string { return identityUserValue(user, field) }
		if identityDirectoryMatchesSearch(needle, fields, value) && identityDirectoryMatchesFilters(filters, value) {
			filtered = append(filtered, user)
		}
	}
	sort.SliceStable(filtered, func(left, right int) bool {
		return identityDirectoryLess(rules,
			func(field string) string { return identityUserValue(filtered[left], field) },
			func(field string) string { return identityUserValue(filtered[right], field) })
	})
	page, err := identityDirectoryPage(cursor, filtered, func(user identitymodel.IdentityUser) string { return user.ID })
	if err != nil {
		return identitymodel.IdentityUserPage{}, err
	}
	return identitymodel.IdentityUserPage{Items: page.Items, PageSize: cursor.PageSize(), Total: len(filtered), HasNext: page.HasNext, NextID: page.NextID}, nil
}

func mapStringAny(values map[string]string) map[string]any {
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func identityRoleAssignmentValue(assignment identitymodel.IdentityUserRoleAssignment, field string) string {
	switch field {
	case "user_id":
		return assignment.UserID
	case "role_id":
		return assignment.RoleID
	case "binding_key":
		return assignment.BindingKey
	case "profile_id":
		return assignment.ProfileID
	case "source":
		return assignment.Source
	case "status":
		return assignment.Status
	case "valid_from":
		return assignment.ValidFrom
	case "valid_until":
		return assignment.ValidUntil
	case "granted_by":
		return assignment.GrantedBy
	case "created_at":
		return assignment.CreatedAt
	default:
		return ""
	}
}

func (s *IdentityDomainService) SearchUserRoleAssignments(ctx context.Context, userID string, query identitymodel.IdentityListQuery) (identitymodel.IdentityUserRoleAssignmentPage, error) {
	assignments, err := s.repo.ListIdentityUserRoleAssignments(ctx, s.workspace, strings.TrimSpace(userID))
	if err != nil {
		return identitymodel.IdentityUserRoleAssignmentPage{}, err
	}
	allowed := map[string]bool{"user_id": true, "role_id": true, "binding_key": true, "profile_id": true, "source": true, "status": true, "valid_from": true, "valid_until": true, "granted_by": true, "created_at": true}
	fields, err := identityDirectoryFields(query.SearchFields, []string{"role_id", "source", "granted_by"}, allowed, "backend.identity.role_assignment_search_field_invalid")
	if err != nil {
		return identitymodel.IdentityUserRoleAssignmentPage{}, err
	}
	filters, err := identityDirectoryFilters(query.Filters, allowed, "backend.identity.role_assignment_filter_field_invalid")
	if err != nil {
		return identitymodel.IdentityUserRoleAssignmentPage{}, err
	}
	rules, err := identityDirectorySort(query, []identitymodel.IdentitySortRule{{Field: "created_at", Direction: "desc"}, {Field: "role_id", Direction: "asc"}}, allowed, "backend.identity.role_assignment_sort_invalid")
	if err != nil {
		return identitymodel.IdentityUserRoleAssignmentPage{}, err
	}
	needle := strings.ToLower(strings.TrimSpace(query.Search))
	filtered := make([]identitymodel.IdentityUserRoleAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		value := func(field string) string { return identityRoleAssignmentValue(assignment, field) }
		if identityDirectoryMatchesSearch(needle, fields, value) && identityDirectoryMatchesFilters(filters, value) {
			filtered = append(filtered, assignment)
		}
	}
	sort.SliceStable(filtered, func(left, right int) bool {
		return identityDirectoryLess(rules,
			func(field string) string { return identityRoleAssignmentValue(filtered[left], field) },
			func(field string) string { return identityRoleAssignmentValue(filtered[right], field) })
	})
	cursor := identityDirectoryPagination(query)
	page, err := identityDirectoryPage(cursor, filtered, func(assignment identitymodel.IdentityUserRoleAssignment) string { return assignment.RoleID })
	if err != nil {
		return identitymodel.IdentityUserRoleAssignmentPage{}, err
	}
	return identitymodel.IdentityUserRoleAssignmentPage{Items: page.Items, PageSize: cursor.PageSize(), Total: len(filtered), HasNext: page.HasNext, NextID: page.NextID}, nil
}
