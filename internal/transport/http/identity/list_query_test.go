package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityHTTPBatchSecurity struct {
	*identityHTTPUserSecurity
	profiles map[string]authdomain.UserSecurityProfile
	err      error
}

func (s *identityHTTPBatchSecurity) UserDirectorySecurityProfiles(context.Context, string, []string) (map[string]authdomain.UserSecurityProfile, error) {
	return s.profiles, s.err
}

func TestIdentityListQueryParsesPaginationSearchFiltersAndSort(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/?after_id=user-25&page_size=25&search=%20alice%20&search_fields=name,%20email,,&filters=%7B%22status%22%3A%22active%22%7D&sort=-created_at,name:DESC,empty", nil)
	query := identityListQuery(request)
	if query.AfterID != "user-25" || query.PageSize != 25 || query.Search != "alice" ||
		len(query.SearchFields) != 2 || query.SearchFields[1] != "email" ||
		query.Filters["status"] != "active" || len(query.Sort) != 3 ||
		query.Sort[0].Field != "created_at" || query.Sort[0].Direction != "desc" ||
		query.Sort[1].Field != "name" || query.Sort[1].Direction != "DESC" ||
		query.Sort[2].Field != "empty" || query.Sort[2].Direction != "asc" {
		t.Fatalf("unexpected query: %#v", query)
	}
	invalid := identityListQuery(httptest.NewRequest(http.MethodGet, "/?filters=not-json&sort=,,,", nil))
	if len(invalid.Filters) != 0 || len(invalid.Sort) != 0 {
		t.Fatalf("invalid optional values must be ignored: %#v", invalid)
	}
}

func TestIdentityUserDirectoryHandlerProjectsSecuritySummary(t *testing.T) {
	repository := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Name: "Alice", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	handler.userSecurity = &identityHTTPUserSecurity{profile: authdomain.UserSecurityProfile{
		Credential: &authdomain.UserCredentialSecuritySummary{LastLoginAt: "2026-07-25T00:00:00Z"},
		MFAEnabled: true, Locked: true, ActiveSessions: 2,
	}}
	recorder, request := identityRoleRequest(http.MethodGet, "/identity/users/directory/search?page=1&page_size=20", "", nil)
	handler.searchIdentityUserDirectory(recorder, request)
	page, ok := response.value.(identityapplication.IdentityUserDirectoryPage)
	if response.status != http.StatusOK || !ok || len(page.Items) != 1 ||
		!page.Items[0].Security.MFAEnabled || page.Items[0].Security.LastLoginAt == "" {
		t.Fatalf("status=%d page=%#v err=%v", response.status, response.value, response.err)
	}
	handler.userSecurity = &identityHTTPUserSecurity{}
	response.status, response.value, response.err = 0, nil, nil
	handler.searchIdentityUserDirectory(recorder, request)
	page, ok = response.value.(identityapplication.IdentityUserDirectoryPage)
	if response.status != http.StatusOK || !ok || len(page.Items) != 1 || page.Items[0].Security.LastLoginAt != "" {
		t.Fatalf("nil credential status=%d page=%#v err=%v", response.status, response.value, response.err)
	}
	handler.userSecurity = &identityHTTPUserSecurity{err: errIdentityHTTPTest}
	response.status, response.value, response.err = 0, nil, nil
	handler.searchIdentityUserDirectory(recorder, request)
	if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
		t.Fatalf("security failure status=%d err=%v", response.status, response.err)
	}
	repository.err = errIdentityHTTPTest
	handler.userSecurity = &identityHTTPUserSecurity{}
	response.status, response.value, response.err = 0, nil, nil
	handler.searchIdentityUserDirectory(recorder, request)
	if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
		t.Fatalf("repository failure status=%d err=%v", response.status, response.err)
	}
}

func TestIdentityUserDirectoryBatchSecurityProjectionAndFailures(t *testing.T) {
	repository := &identityHTTPRepository{users: []identitymodel.IdentityUser{
		{ID: "user-1", Name: "Alice", Status: identitymodel.IdentityStatusActive},
		{ID: "user-2", Name: "Bob", Status: identitymodel.IdentityStatusActive},
	}}
	handler, response := newIdentityHTTPHandler(repository)
	batch := &identityHTTPBatchSecurity{
		identityHTTPUserSecurity: &identityHTTPUserSecurity{},
		profiles: map[string]authdomain.UserSecurityProfile{
			"user-1": {
				Credential: &authdomain.UserCredentialSecuritySummary{LastLoginAt: "2026-07-25T00:00:00Z"},
				MFAEnabled: true,
			},
			"user-2": {Locked: true},
		},
	}
	handler.userSecurity = batch
	recorder, request := identityRoleRequest(http.MethodGet, "/identity/users/directory/search?page=1&page_size=20", "", nil)
	handler.searchIdentityUserDirectory(recorder, request)
	page, ok := response.value.(identityapplication.IdentityUserDirectoryPage)
	if response.status != http.StatusOK || !ok || len(page.Items) != 2 {
		t.Fatalf("status=%d page=%#v err=%v", response.status, response.value, response.err)
	}
	if page.Items[0].Security.LastLoginAt == "" || page.Items[1].Security.LastLoginAt != "" {
		t.Fatalf("batch summaries=%+v", page.Items)
	}

	batch.err = errIdentityHTTPTest
	response.status, response.value, response.err = 0, nil, nil
	handler.searchIdentityUserDirectory(recorder, request)
	if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
		t.Fatalf("batch failure status=%d err=%v", response.status, response.err)
	}
}

func TestIdentityPagedListHandlers(t *testing.T) {
	repository := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{
			{ID: "user-2", Name: "Bob", Email: "bob@example.test", Status: identitymodel.IdentityStatusDisabled},
			{ID: "user-1", Name: "Alice", Email: "alice@example.test", Status: identitymodel.IdentityStatusActive},
		},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{
			{ID: "worker-1", IdentityUserID: "user-1", OrganizationID: "org", WorkerNo: "001", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive},
		},
		assignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "user-1", RoleID: "viewer", Source: "manual", Status: "active"},
		},
	}
	handler, response := newIdentityHTTPHandler(repository)
	tests := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		url  string
		path map[string]string
	}{
		{name: "users", call: handler.searchIdentityUsers, url: "/identity/users/search?page=1&page_size=1&search=alice&filters=%7B%22status%22%3A%22active%22%7D&sort=name:asc"},
		{name: "workforce", call: handler.searchIdentityWorkforceProfiles, url: "/identity/workforce/search?page=1&page_size=10&search=001&sort=worker_no:asc"},
		{name: "assignments", call: handler.searchIdentityUserRoleAssignments, url: "/identity/users/user-1/role-assignments/search?page=1&page_size=10&search=viewer&sort=role_id:asc", path: map[string]string{"userID": " user-1 "}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response.status, response.value, response.err = 0, nil, nil
			recorder, request := identityRoleRequest(http.MethodGet, test.url, "", test.path)
			test.call(recorder, request)
			if response.status != http.StatusOK || response.err != nil || response.value == nil {
				t.Fatalf("status=%d value=%#v err=%v", response.status, response.value, response.err)
			}
		})
	}
	repository.err = errIdentityHTTPTest
	for _, test := range tests {
		response.status, response.value, response.err = 0, nil, nil
		recorder, request := identityRoleRequest(http.MethodGet, test.url, "", test.path)
		test.call(recorder, request)
		if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
			t.Fatalf("%s failure status=%d err=%v", test.name, response.status, response.err)
		}
	}
}
