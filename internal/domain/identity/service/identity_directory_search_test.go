package service

import (
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func directorySearchService(t *testing.T, repository *identityRolesRepositoryStub) *IdentityDomainService {
	t.Helper()
	service, err := NewIdentityDomainService(repository, nil).ForWorkspace("default")
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestIdentityDirectorySearchUsers(t *testing.T) {
	repository := &identityRolesRepositoryStub{users: []identitymodel.IdentityUser{
		{ID: "u-2", Name: "Bob", Email: "bob@example.test", Phone: "200", Status: identitymodel.IdentityStatusDisabled},
		{ID: "u-1", Name: "Alice", Email: "alice@example.test", Phone: "100", Status: identitymodel.IdentityStatusActive},
		{ID: "u-3", Name: "Alice", Email: "other@example.test", Phone: "300", Status: identitymodel.IdentityStatusActive},
	}}
	service := directorySearchService(t, repository)
	page, err := service.SearchUsers(t.Context(), identitymodel.IdentityListQuery{
		PageSize: 1, Search: "ali", SearchFields: []string{"name"},
		Filters: map[string]any{"status": "ACTIVE"},
		Sort:    []identitymodel.IdentitySortRule{{Field: "email", Direction: "desc"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 1 || page.Items[0].ID != "u-3" || !page.HasNext {
		t.Fatalf("unexpected page: %#v", page)
	}
	page, err = service.SearchUsers(t.Context(), identitymodel.IdentityListQuery{PageSize: 999})
	if err != nil || page.PageSize != identityDirectoryMaximumPageSize || len(page.Items) != 3 || page.HasNext {
		t.Fatalf("unexpected bounded page: %#v, %v", page, err)
	}
	if page, err = service.SearchUsers(t.Context(), identitymodel.IdentityListQuery{Search: "alice", Filters: map[string]any{"status": "disabled"}}); err != nil || page.Total != 0 {
		t.Fatalf("mismatched user filter: %#v, %v", page, err)
	}
	for _, test := range []struct {
		query identitymodel.IdentityListQuery
		code  string
	}{
		{query: identitymodel.IdentityListQuery{SearchFields: []string{"secret"}}, code: "backend.identity.user_search_field_invalid"},
		{query: identitymodel.IdentityListQuery{Filters: map[string]any{"secret": "x"}}, code: "backend.identity.user_filter_field_invalid"},
		{query: identitymodel.IdentityListQuery{Sort: []identitymodel.IdentitySortRule{{Field: "secret", Direction: "asc"}}}, code: "backend.identity.user_sort_invalid"},
		{query: identitymodel.IdentityListQuery{Sort: []identitymodel.IdentitySortRule{{Field: "name", Direction: "sideways"}}}, code: "backend.identity.user_sort_invalid"},
	} {
		if _, err := service.SearchUsers(t.Context(), test.query); apperror.CodeOf(err) != test.code {
			t.Fatalf("expected %s, got %v", test.code, err)
		}
	}
	repository.listUsersErr = errors.New("users unavailable")
	if _, err := service.SearchUsers(t.Context(), identitymodel.IdentityListQuery{}); !errors.Is(err, repository.listUsersErr) {
		t.Fatalf("expected repository error, got %v", err)
	}
}

func TestIdentityDirectorySearchWorkforceAndAssignments(t *testing.T) {
	repository := &identityRolesRepositoryStub{
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{
			{ID: "w-2", OrganizationID: "org-b", IdentityUserID: "u-2", WorkerNo: "002", WorkerType: identitymodel.IdentityWorkerContractor, WorkStatus: identitymodel.IdentityWorkSuspended, StartDate: "2025-01-01", EndDate: "2026-01-01"},
			{ID: "w-1", OrganizationID: "org-a", IdentityUserID: "u-1", WorkerNo: "001", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, StartDate: "2024-01-01"},
		},
		assignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "u-1", RoleID: "viewer", WorkforceProfileID: "w-1", BindingKey: "member", ProfileID: "p-1", Source: "manual", Status: "active", ValidFrom: "2025-01-01", ValidUntil: "2026-01-01", GrantedBy: "admin", CreatedAt: "2025-02-01"},
			{UserID: "u-1", RoleID: "editor", Source: "request", Status: "revoked", CreatedAt: "2025-01-01"},
		},
	}
	service := directorySearchService(t, repository)
	workforce, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{
		Search: "org-a", Filters: map[string]any{"work_status": "active"},
		Sort: []identitymodel.IdentitySortRule{{Field: "start_date", Direction: "desc"}},
	})
	if err != nil || workforce.Total != 1 || workforce.Items[0].ID != "w-1" {
		t.Fatalf("unexpected workforce page: %#v, %v", workforce, err)
	}
	if workforce, err = service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{}); err != nil || workforce.Total != 2 {
		t.Fatalf("unexpected unfiltered workforce page: %#v, %v", workforce, err)
	}
	if workforce, err = service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{Search: "org", Filters: map[string]any{"work_status": "missing"}}); err != nil || workforce.Total != 0 {
		t.Fatalf("mismatched workforce filter: %#v, %v", workforce, err)
	}
	assignments, err := service.SearchUserRoleAssignments(t.Context(), " u-1 ", identitymodel.IdentityListQuery{
		Search: "admin", SearchFields: []string{"granted_by"}, Filters: map[string]any{"status": "active"},
		Sort: []identitymodel.IdentitySortRule{{Field: "created_at", Direction: "asc"}},
	})
	if err != nil || assignments.Total != 1 || assignments.Items[0].RoleID != "viewer" {
		t.Fatalf("unexpected assignment page: %#v, %v", assignments, err)
	}
	if assignments, err = service.SearchUserRoleAssignments(t.Context(), "u-1", identitymodel.IdentityListQuery{}); err != nil || assignments.Total != 2 {
		t.Fatalf("unexpected unfiltered assignment page: %#v, %v", assignments, err)
	}
	if assignments, err = service.SearchUserRoleAssignments(t.Context(), "u-1", identitymodel.IdentityListQuery{Search: "manual", Filters: map[string]any{"status": "missing"}}); err != nil || assignments.Total != 0 {
		t.Fatalf("mismatched assignment filter: %#v, %v", assignments, err)
	}
	repository.listAssignmentsErr = errors.New("assignments unavailable")
	if _, err := service.SearchUserRoleAssignments(t.Context(), "u-1", identitymodel.IdentityListQuery{}); !errors.Is(err, repository.listAssignmentsErr) {
		t.Fatalf("expected assignment repository error, got %v", err)
	}
	repository.listAssignmentsErr = nil
	repository.err = errors.New("workforce unavailable")
	if _, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{}); !errors.Is(err, repository.err) {
		t.Fatalf("expected workforce repository error, got %v", err)
	}
}

func TestIdentityDirectorySearchHelpersAndValidation(t *testing.T) {
	if size := identityDirectoryPagination(identitymodel.IdentityListQuery{PageSize: -1}).PageSize(); size != 20 {
		t.Fatalf("unexpected default: %d", size)
	}
	if !identityDirectoryMatchesSearch("", nil, func(string) string { return "" }) {
		t.Fatal("empty search must match")
	}
	if identityDirectoryMatchesSearch("x", []string{"name"}, func(string) string { return "no" }) {
		t.Fatal("non-matching search must fail")
	}
	if identityDirectoryMatchesFilters(map[string]string{"status": "active"}, func(string) string { return "disabled" }) {
		t.Fatal("non-matching filter must fail")
	}
	if !identityDirectoryMatchesFilters(nil, func(string) string { return "" }) {
		t.Fatal("empty filters must match")
	}
	if identityDirectoryLess(
		[]identitymodel.IdentitySortRule{{Field: "name", Direction: "asc"}},
		func(string) string { return "same" },
		func(string) string { return "same" },
	) {
		t.Fatal("equal values must not sort before")
	}
	if !identityDirectoryLess(
		[]identitymodel.IdentitySortRule{{Field: "name", Direction: "desc"}},
		func(string) string { return "z" },
		func(string) string { return "a" },
	) {
		t.Fatal("descending comparison failed")
	}
	for _, field := range []string{"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "account_type", "locale", "timezone", "email", "phone", "status", "unknown"} {
		_ = identityUserValue(identitymodel.IdentityUser{}, field)
	}
	for _, field := range []string{"id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "unknown"} {
		_ = identityWorkforceValue(identitymodel.IdentityWorkforceProfile{}, field)
	}
	for _, field := range []string{"user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "created_at", "unknown"} {
		_ = identityRoleAssignmentValue(identitymodel.IdentityUserRoleAssignment{}, field)
	}
	withoutWorkforce, err := NewIdentityDomainService(&identityDepartmentUserRepository{}, nil).ForWorkspace("default")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutWorkforce.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{}); apperror.CodeOf(err) != "backend.identity.workforce_unavailable" {
		t.Fatalf("expected workforce capability error, got %v", err)
	}
}

func TestIdentityDirectoryWorkforceAndAssignmentInvalidFields(t *testing.T) {
	service := directorySearchService(t, &identityRolesRepositoryStub{})
	cases := []struct {
		run  func() error
		code string
	}{
		{run: func() error {
			_, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{SearchFields: []string{"x"}})
			return err
		}, code: "backend.identity.workforce_search_field_invalid"},
		{run: func() error {
			_, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{Filters: map[string]any{"x": "y"}})
			return err
		}, code: "backend.identity.workforce_filter_field_invalid"},
		{run: func() error {
			_, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{Sort: []identitymodel.IdentitySortRule{{Field: "x", Direction: "asc"}}})
			return err
		}, code: "backend.identity.workforce_sort_invalid"},
		{run: func() error {
			_, err := service.SearchUserRoleAssignments(t.Context(), "", identitymodel.IdentityListQuery{SearchFields: []string{"x"}})
			return err
		}, code: "backend.identity.role_assignment_search_field_invalid"},
		{run: func() error {
			_, err := service.SearchUserRoleAssignments(t.Context(), "", identitymodel.IdentityListQuery{Filters: map[string]any{"x": "y"}})
			return err
		}, code: "backend.identity.role_assignment_filter_field_invalid"},
		{run: func() error {
			_, err := service.SearchUserRoleAssignments(t.Context(), "", identitymodel.IdentityListQuery{Sort: []identitymodel.IdentitySortRule{{Field: "x", Direction: "asc"}}})
			return err
		}, code: "backend.identity.role_assignment_sort_invalid"},
	}
	for _, test := range cases {
		if err := test.run(); apperror.CodeOf(err) != test.code {
			t.Fatalf("expected %s, got %v", test.code, err)
		}
	}
}
