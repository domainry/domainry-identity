package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const identityDirectoryMaximumPageSize = 200

func identityDirectoryPage(query identitymodel.IdentityListQuery) (int, int) {
	page := query.Page
	if page < 1 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > identityDirectoryMaximumPageSize {
		pageSize = identityDirectoryMaximumPageSize
	}
	return page, pageSize
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

func identityDirectorySlice[T any](items []T, page, pageSize int) ([]T, bool) {
	start := (page - 1) * pageSize
	if start > len(items) {
		start = len(items)
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end], end < len(items)
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
		"account_type": true, "locale": true, "timezone": true, "email": true, "phone": true, "status": true,
	}
	fields, err := identityDirectoryFields(query.SearchFields, []string{"name", "given_name", "middle_name", "family_name", "native_name", "email", "phone"}, allowed, "backend.identity.user_search_field_invalid")
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
	page, pageSize := identityDirectoryPage(query)
	query.Page, query.PageSize, query.SearchFields, query.Filters, query.Sort = page, pageSize, fields, mapStringAny(filters), rules
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
	items, hasNext := identityDirectorySlice(filtered, page, pageSize)
	return identitymodel.IdentityUserPage{Items: items, Page: page, PageSize: pageSize, Total: len(filtered), HasNext: hasNext}, nil
}

func identityWorkforceValue(profile identitymodel.IdentityWorkforceProfile, field string) string {
	switch field {
	case "id":
		return profile.ID
	case "organization_id":
		return profile.OrganizationID
	case "identity_user_id":
		return profile.IdentityUserID
	case "worker_no":
		return profile.WorkerNo
	case "worker_type":
		return string(profile.WorkerType)
	case "work_status":
		return string(profile.WorkStatus)
	case "start_date":
		return profile.StartDate
	case "end_date":
		return profile.EndDate
	default:
		return ""
	}
}

func (s *IdentityDomainService) SearchWorkforceProfiles(ctx context.Context, query identitymodel.IdentityListQuery) (identitymodel.IdentityWorkforceProfilePage, error) {
	workforce, ok := s.repo.(interface {
		ListIdentityWorkforceProfiles(context.Context, string) ([]identitymodel.IdentityWorkforceProfile, error)
	})
	if !ok {
		return identitymodel.IdentityWorkforceProfilePage{}, badRequest("backend.identity.workforce_unavailable")
	}
	allowed := map[string]bool{"id": true, "organization_id": true, "identity_user_id": true, "worker_no": true, "worker_type": true, "work_status": true, "start_date": true, "end_date": true}
	fields, err := identityDirectoryFields(query.SearchFields, []string{"worker_no", "identity_user_id", "organization_id"}, allowed, "backend.identity.workforce_search_field_invalid")
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	filters, err := identityDirectoryFilters(query.Filters, allowed, "backend.identity.workforce_filter_field_invalid")
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	rules, err := identityDirectorySort(query, []identitymodel.IdentitySortRule{{Field: "worker_no", Direction: "asc"}, {Field: "id", Direction: "asc"}}, allowed, "backend.identity.workforce_sort_invalid")
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	page, pageSize := identityDirectoryPage(query)
	query.Page, query.PageSize, query.SearchFields, query.Filters, query.Sort = page, pageSize, fields, mapStringAny(filters), rules
	if repository, ok := s.repo.(interface {
		SearchIdentityWorkforceProfiles(context.Context, string, identitymodel.IdentityListQuery) (identitymodel.IdentityWorkforceProfilePage, error)
	}); ok && (strings.TrimSpace(query.Scope) == "" || strings.TrimSpace(query.Scope) == "all_records") {
		return repository.SearchIdentityWorkforceProfiles(ctx, s.workspace, query)
	}
	profiles, err := workforce.ListIdentityWorkforceProfiles(ctx, s.workspace)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	needle := strings.ToLower(strings.TrimSpace(query.Search))
	filtered := make([]identitymodel.IdentityWorkforceProfile, 0, len(profiles))
	allowedProfileIDs, err := s.identityWorkforceScopedProfileIDs(ctx, query, profiles)
	if err != nil {
		return identitymodel.IdentityWorkforceProfilePage{}, err
	}
	for _, profile := range profiles {
		if allowedProfileIDs != nil && !allowedProfileIDs[profile.ID] {
			continue
		}
		value := func(field string) string { return identityWorkforceValue(profile, field) }
		if identityDirectoryMatchesSearch(needle, fields, value) && identityDirectoryMatchesFilters(filters, value) {
			filtered = append(filtered, profile)
		}
	}
	sort.SliceStable(filtered, func(left, right int) bool {
		return identityDirectoryLess(rules,
			func(field string) string { return identityWorkforceValue(filtered[left], field) },
			func(field string) string { return identityWorkforceValue(filtered[right], field) })
	})
	items, hasNext := identityDirectorySlice(filtered, page, pageSize)
	return identitymodel.IdentityWorkforceProfilePage{Items: items, Page: page, PageSize: pageSize, Total: len(filtered), HasNext: hasNext}, nil
}

func (s *IdentityDomainService) identityWorkforceScopedProfileIDs(ctx context.Context, query identitymodel.IdentityListQuery, profiles []identitymodel.IdentityWorkforceProfile) (map[string]bool, error) {
	scope := strings.TrimSpace(query.Scope)
	if scope == "" || scope == "all_records" {
		return nil, nil
	}
	allowed := map[string]bool{}
	for _, profile := range profiles {
		if profile.IdentityUserID == strings.TrimSpace(query.PrincipalUserID) &&
			(scope == "owned_records" || scope == "subordinates" || scope == "team" || scope == "department" || scope == "department_and_children") {
			allowed[profile.ID] = true
		}
	}
	if scope == "owned_records" || scope == "none" || scope == "custom" {
		return allowed, nil
	}
	if scope == "subordinates" || scope == "team" {
		users := map[string]bool{}
		for _, userID := range query.PrincipalReportingUserIDs {
			users[strings.TrimSpace(userID)] = true
		}
		for _, profile := range profiles {
			if users[profile.IdentityUserID] {
				allowed[profile.ID] = true
			}
		}
		return allowed, nil
	}
	if scope != "department" && scope != "department_and_children" {
		return allowed, nil
	}
	repository := s.workforceRepository()
	if repository == nil {
		return nil, internalError("identity workforce repository", nil)
	}
	assignments, err := repository.ListIdentityWorkforceAssignments(ctx, s.workspace, "")
	if err != nil {
		return nil, err
	}
	departments, err := s.repo.ListIdentityDepartments(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	departmentPaths := make(map[string]string, len(departments))
	for _, department := range departments {
		departmentPaths[department.ID] = strings.TrimRight(strings.TrimSpace(department.Path), "/")
	}
	principalPath := strings.TrimRight(strings.TrimSpace(query.PrincipalDepartmentPath), "/")
	for _, profile := range profiles {
		assignment, found := workforcePrimaryAssignmentForSearch(profile, assignments)
		if !found {
			continue
		}
		targetPath := departmentPaths[assignment.OrganizationUnitID]
		if principalPath != "" && (targetPath == principalPath || scope == "department_and_children" && strings.HasPrefix(targetPath, principalPath+"/")) {
			allowed[profile.ID] = true
		}
	}
	return allowed, nil
}

func workforcePrimaryAssignmentForSearch(profile identitymodel.IdentityWorkforceProfile, assignments []identitymodel.IdentityWorkforceAssignment) (identitymodel.IdentityWorkforceAssignment, bool) {
	for _, assignment := range assignments {
		if assignment.WorkforceProfileID != profile.ID {
			continue
		}
		if profile.PrimaryAssignmentID != "" && assignment.ID == profile.PrimaryAssignmentID {
			return assignment, true
		}
	}
	for _, assignment := range assignments {
		if assignment.WorkforceProfileID == profile.ID && assignment.AssignmentType == identitymodel.IdentityWorkforceAssignmentPrimary && assignment.Status == identitymodel.IdentityStatusActive {
			return assignment, true
		}
	}
	return identitymodel.IdentityWorkforceAssignment{}, false
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
	case "workforce_profile_id":
		return assignment.WorkforceProfileID
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
	allowed := map[string]bool{"user_id": true, "role_id": true, "workforce_profile_id": true, "binding_key": true, "profile_id": true, "source": true, "status": true, "valid_from": true, "valid_until": true, "granted_by": true, "created_at": true}
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
	page, pageSize := identityDirectoryPage(query)
	items, hasNext := identityDirectorySlice(filtered, page, pageSize)
	return identitymodel.IdentityUserRoleAssignmentPage{Items: items, Page: page, PageSize: pageSize, Total: len(filtered), HasNext: hasNext}, nil
}
