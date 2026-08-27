package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityAuthorizationMiddlewareMatrix(t *testing.T) {
	var principal identitymodel.Principal
	denials := 0
	handler := NewIdentityHandler(IdentityDependencies{
		Principal: func(*http.Request) identitymodel.Principal { return principal },
		WriteError: func(w http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) {
			w.WriteHeader(status)
		},
		SecurityAudit: func(*http.Request, string, string, map[string]any) { denials++ },
	})
	next := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	tests := []struct {
		name       string
		wrap       func(http.HandlerFunc) http.HandlerFunc
		principal  identitymodel.Principal
		pathValues map[string]string
		wantStatus int
	}{
		{name: "permission denied", wrap: func(next http.HandlerFunc) http.HandlerFunc {
			return handler.identityPermission("identity.user.read", next)
		}, principal: identitymodel.Principal{Known: true}, wantStatus: http.StatusForbidden},
		{name: "permission unknown", wrap: func(next http.HandlerFunc) http.HandlerFunc {
			return handler.identityPermission("identity.user.read", next)
		}, wantStatus: http.StatusForbidden},
		{name: "permission allowed", wrap: func(next http.HandlerFunc) http.HandlerFunc {
			return handler.identityPermission("identity.user.read", next)
		}, principal: identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: []string{"identity.user.read"}}}, wantStatus: http.StatusNoContent},
		{name: "all permissions unknown", wrap: func(next http.HandlerFunc) http.HandlerFunc {
			return handler.identityPermissions([]string{"identity.users.write", "identity.roles.write"}, next)
		}, wantStatus: http.StatusForbidden},
		{name: "all permissions missing one", wrap: func(next http.HandlerFunc) http.HandlerFunc {
			return handler.identityPermissions([]string{"identity.users.write", "identity.roles.write"}, next)
		}, principal: identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: []string{"identity.users.write"}}}, wantStatus: http.StatusForbidden},
		{name: "all permissions allowed", wrap: func(next http.HandlerFunc) http.HandlerFunc {
			return handler.identityPermissions([]string{"identity.users.write", "identity.roles.write"}, next)
		}, principal: identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: []string{"identity.users.write", "identity.roles.write"}}}, wantStatus: http.StatusNoContent},
		{name: "self allowed", wrap: func(next http.HandlerFunc) http.HandlerFunc {
			return handler.identityPermissionOrSelf("identity.user.update", "userID", next)
		}, principal: identitymodel.Principal{Known: true, UserID: "user-1"}, pathValues: map[string]string{"userID": "user-1"}, wantStatus: http.StatusNoContent},
		{name: "non-self denied", wrap: func(next http.HandlerFunc) http.HandlerFunc {
			return handler.identityPermissionOrSelf("identity.user.update", "userID", next)
		}, principal: identitymodel.Principal{Known: true, UserID: "user-1"}, pathValues: map[string]string{"userID": "user-2"}, wantStatus: http.StatusForbidden},
		{name: "non-self unknown", wrap: func(next http.HandlerFunc) http.HandlerFunc {
			return handler.identityPermissionOrSelf("identity.user.update", "userID", next)
		}, pathValues: map[string]string{"userID": "user-2"}, wantStatus: http.StatusForbidden},
		{name: "non-self permission", wrap: func(next http.HandlerFunc) http.HandlerFunc {
			return handler.identityPermissionOrSelf("identity.user.update", "userID", next)
		}, principal: identitymodel.Principal{Known: true, UserID: "user-1", Role: identitymodel.RoleSchema{Permissions: []string{"identity.user.update"}}}, pathValues: map[string]string{"userID": "user-2"}, wantStatus: http.StatusNoContent},
		{name: "authenticated denied", wrap: handler.Authenticated, wantStatus: http.StatusForbidden},
		{name: "authenticated allowed", wrap: handler.Authenticated, principal: identitymodel.Principal{Known: true}, wantStatus: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			principal = test.principal
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/identity/test", nil)
			for key, value := range test.pathValues {
				request.SetPathValue(key, value)
			}
			test.wrap(next).ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d", response.Code, test.wantStatus)
			}
		})
	}
	if denials != 7 {
		t.Fatalf("security denials=%d", denials)
	}
}

func TestIdentityAdminMiddlewareMatrix(t *testing.T) {
	var principal identitymodel.Principal
	denials := 0
	handler := NewIdentityHandler(IdentityDependencies{
		Principal: func(*http.Request) identitymodel.Principal { return principal },
		WriteError: func(w http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) {
			w.WriteHeader(status)
		},
		SecurityAudit: func(*http.Request, string, string, map[string]any) { denials++ },
	})
	next := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	tests := []struct {
		name       string
		principal  identitymodel.Principal
		wantStatus int
	}{
		{name: "unknown principal", wantStatus: http.StatusForbidden},
		{name: "permission missing", principal: identitymodel.Principal{Known: true}, wantStatus: http.StatusForbidden},
		{
			name: "allowed",
			principal: identitymodel.Principal{
				Known: true,
				Role:  identitymodel.RoleSchema{Permissions: []string{"workspace.admin"}},
			},
			wantStatus: http.StatusNoContent,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			principal = test.principal
			response := httptest.NewRecorder()
			handler.Admin(next).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/test", nil))
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d", response.Code, test.wantStatus)
			}
		})
	}
	if denials != 2 {
		t.Fatalf("security denials=%d", denials)
	}
}

func TestEffectiveMenusRejectsUnknownPrincipalAndPropagatesServiceError(t *testing.T) {
	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
	handler.principal = func(*http.Request) identitymodel.Principal { return identitymodel.Principal{} }
	handler.EffectiveMenus(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/identity/effective-menus?surface=admin_console", nil))
	if response.status != http.StatusForbidden {
		t.Fatalf("unknown principal status=%d", response.status)
	}

	handler, response = newIdentityHTTPHandler(&identityHTTPRepository{})
	surfaceFreeRequest := httptest.NewRequest(http.MethodGet, "/identity/effective-menus", nil)
	surfaceFreeRequest = surfaceFreeRequest.WithContext(requestcontext.WithWorkspaceID(surfaceFreeRequest.Context(), "workspace-1"))
	handler.EffectiveMenus(httptest.NewRecorder(), surfaceFreeRequest)
	if response.status != http.StatusOK {
		t.Fatalf("surface-free effective menus status=%d", response.status)
	}

	handler, response = newIdentityHTTPHandler(&identityHTTPRepository{err: errIdentityHTTPTest})
	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{
			Known:  true,
			UserID: "reviewer-1",
			Role:   identitymodel.RoleSchema{},
		}
	}
	handler.EffectiveMenus(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/identity/effective-menus?surface=admin_console", nil))
	if response.status != http.StatusInternalServerError || response.err == nil {
		t.Fatalf("service status=%d error=%v", response.status, response.err)
	}

	handler, response = newIdentityHTTPHandler(&identityHTTPRepository{})
	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{
			Known:  true,
			UserID: "reviewer-1",
			Role:   identitymodel.RoleSchema{},
		}
	}
	successRequest := httptest.NewRequest(http.MethodGet, "/identity/effective-menus?surface=admin_console", nil)
	successRequest = successRequest.WithContext(requestcontext.WithWorkspaceID(successRequest.Context(), "workspace-1"))
	handler.EffectiveMenus(httptest.NewRecorder(), successRequest)
	if response.status != http.StatusOK || response.err != nil {
		t.Fatalf("success status=%d error=%v", response.status, response.err)
	}

}

func TestIdentityDepartmentHandlers(t *testing.T) {
	repository := &identityHTTPRepository{departments: []identitymodel.IdentityDepartment{{ID: "department-1", Name: "Sales"}}}
	handler, response := newIdentityHTTPHandler(repository)
	w, request := identityRoleRequest(http.MethodGet, "/identity/departments", "", nil)
	handler.listIdentityDepartments(w, request)
	departments, ok := response.value.([]identitymodel.IdentityDepartment)
	if response.status != http.StatusOK || !ok || len(departments) != 1 {
		t.Fatalf("list status=%d value=%#v err=%v", response.status, response.value, response.err)
	}

	tests := []struct {
		name       string
		call       func(http.ResponseWriter, *http.Request)
		body       string
		pathValues map[string]string
		wantStatus int
		wantID     string
	}{
		{name: "create", call: handler.createIdentityDepartment, body: `{"id":"department-2","name":"Finance"}`, wantStatus: http.StatusCreated, wantID: "department-2"},
		{name: "update path id", call: handler.updateIdentityDepartment, body: `{"id":"body-id","name":"Operations"}`, pathValues: map[string]string{"departmentID": " department-3 "}, wantStatus: http.StatusOK, wantID: "department-3"},
		{name: "update body id", call: handler.updateIdentityDepartment, body: `{"id":"body-id","name":"Operations"}`, pathValues: map[string]string{"departmentID": " "}, wantStatus: http.StatusOK, wantID: "body-id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response.status, response.value, response.err = 0, nil, nil
			w, request := identityRoleRequest(http.MethodPost, "/identity/departments/test", test.body, test.pathValues)
			test.call(w, request)
			if response.status != test.wantStatus || repository.lastDepartment.ID != test.wantID {
				t.Fatalf("status=%d department=%+v err=%v", response.status, repository.lastDepartment, response.err)
			}
		})
	}
}

func TestIdentityDepartmentHandlersRejectDecodeAndRepositoryFailures(t *testing.T) {
	for _, call := range []func(*IdentityHandler, http.ResponseWriter, *http.Request){
		func(handler *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			handler.createIdentityDepartment(w, r)
		},
		func(handler *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			handler.updateIdentityDepartment(w, r)
		},
	} {
		repository := &identityHTTPRepository{}
		handler, response := newIdentityHTTPHandler(repository)
		w, request := identityRoleRequest(http.MethodPost, "/identity/departments", `{`, nil)
		call(handler, w, request)
		if response.status != http.StatusBadRequest {
			t.Fatalf("invalid JSON status=%d", response.status)
		}
	}
	for _, test := range []struct {
		name string
		repo *identityHTTPRepository
		call func(*IdentityHandler, http.ResponseWriter, *http.Request)
		body string
	}{
		{name: "list", repo: &identityHTTPRepository{listDepartmentsErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.listIdentityDepartments(w, r) }},
		{name: "create", repo: &identityHTTPRepository{upsertDepartmentErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.createIdentityDepartment(w, r) }, body: `{"id":"department-1","name":"Sales"}`},
		{name: "update", repo: &identityHTTPRepository{upsertDepartmentErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.updateIdentityDepartment(w, r) }, body: `{"id":"department-1","name":"Sales"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(test.repo)
			w, request := identityRoleRequest(http.MethodPost, "/identity/departments", test.body, nil)
			test.call(handler, w, request)
			if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
				t.Fatalf("status=%d err=%v", response.status, response.err)
			}
		})
	}
}

func TestIdentityDepartmentOwnerControlledAuthoringCurrentResource(t *testing.T) {
	tests := []struct {
		name        string
		update      bool
		repository  *identityHTTPRepository
		expected    string
		wantStatus  int
		wantUpserts int
	}{
		{
			name:       "create current load failure",
			repository: &identityHTTPRepository{listDepartmentsErr: errIdentityHTTPTest},
			expected:   "empty",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "create current match",
			repository: &identityHTTPRepository{departments: []identitymodel.IdentityDepartment{{ID: "department-1", Name: "Existing"}}},
			wantStatus: http.StatusCreated, wantUpserts: 1,
		},
		{
			name: "create current miss",
			repository: &identityHTTPRepository{
				departments:             []identitymodel.IdentityDepartment{{ID: "department-other", Name: "Other"}},
				storeDepartmentOnUpsert: true,
			},
			expected:   "empty",
			wantStatus: http.StatusCreated, wantUpserts: 1,
		},
		{
			name:       "update current load failure",
			update:     true,
			repository: &identityHTTPRepository{listDepartmentsErr: errIdentityHTTPTest},
			expected:   "empty",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "update current match",
			update:     true,
			repository: &identityHTTPRepository{departments: []identitymodel.IdentityDepartment{{ID: "department-1", Name: "Existing"}}},
			wantStatus: http.StatusOK, wantUpserts: 1,
		},
		{
			name:   "update current miss",
			update: true,
			repository: &identityHTTPRepository{
				departments:             []identitymodel.IdentityDepartment{{ID: "department-other", Name: "Other"}},
				storeDepartmentOnUpsert: true,
			},
			expected:   "empty",
			wantStatus: http.StatusOK, wantUpserts: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(test.repository)
			handler.principal = func(*http.Request) identitymodel.Principal {
				return identitymodel.Principal{
					Known: true, WorkspaceID: "workspace-1", UserID: "builder",
					Role: identitymodel.RoleSchema{Permissions: []string{"identity.departments.write"}},
				}
			}
			if test.expected == "" {
				var err error
				test.expected, err = identityAuthoringResourceHash(
					"identity.department",
					"department-1",
					test.repository.departments[0],
					true,
				)
				if err != nil {
					t.Fatalf("resource hash: %v", err)
				}
			}
			w, request := identityRoleRequest(
				http.MethodPost,
				"/identity/departments/department-1",
				`{"id":"department-1","name":"Changed"}`,
				map[string]string{"departmentID": "department-1"},
			)
			request.Header.Set("Builder-Task-ID", "task-1")
			request.Header.Set("Idempotency-Key", "department-"+test.name)
			request.Header.Set("Expected-Schema-Hash", test.expected)
			if test.update {
				handler.updateIdentityDepartment(w, request)
			} else {
				handler.createIdentityDepartment(w, request)
			}
			if response.status != test.wantStatus || test.repository.upsertDepartmentCalls != test.wantUpserts {
				t.Fatalf("status=%d err=%v upserts=%d", response.status, response.err, test.repository.upsertDepartmentCalls)
			}
		})
	}
}
