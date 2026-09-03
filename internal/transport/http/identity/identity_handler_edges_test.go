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
	permissionCatalog, _ := newIdentityHTTPPermissionCatalog()
	handler := NewIdentityHandler(IdentityDependencies{
		Principal: func(*http.Request) identitymodel.Principal { return principal },
		WriteError: func(w http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) {
			w.WriteHeader(status)
		},
		SecurityAudit:     func(*http.Request, string, string, map[string]any) { denials++ },
		PermissionCatalog: permissionCatalog,
	})
	next := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	tests := []struct {
		name       string
		actionKey  string
		principal  identitymodel.Principal
		pathValues map[string]string
		wantStatus int
	}{
		{name: "permission denied", actionKey: "identity.roles.list", principal: identitymodel.Principal{Known: true}, wantStatus: http.StatusForbidden},
		{name: "permission unknown", actionKey: "identity.roles.list", wantStatus: http.StatusUnauthorized},
		{name: "another exact Permission is not alias", actionKey: "identity.roles.list", principal: identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.permissions.list")}}, wantStatus: http.StatusForbidden},
		{name: "permission allowed", actionKey: "identity.roles.list", principal: identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list")}}, wantStatus: http.StatusNoContent},
		{name: "self requires exact owner Permission", actionKey: "identity.users.get", principal: identitymodel.Principal{Known: true, UserID: "user-1", Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeOwner, "identity.users.get")}}, pathValues: map[string]string{"userID": "user-1"}, wantStatus: http.StatusNoContent},
		{name: "non-self denied", actionKey: "identity.users.get", principal: identitymodel.Principal{Known: true, UserID: "user-1"}, pathValues: map[string]string{"userID": "user-2"}, wantStatus: http.StatusForbidden},
		{name: "non-self permission", actionKey: "identity.users.get", principal: identitymodel.Principal{Known: true, UserID: "user-1", Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.users.get")}}, pathValues: map[string]string{"userID": "user-2"}, wantStatus: http.StatusNoContent},
		{name: "authenticated denied", actionKey: "identity.effective_menus.get", wantStatus: http.StatusUnauthorized},
		{name: "authenticated allowed", actionKey: "identity.effective_menus.get", principal: identitymodel.Principal{Known: true}, wantStatus: http.StatusNoContent},
		{name: "domain self still requires exact Permission", actionKey: "identity.profile_bindings.get", principal: identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeOwner, "identity.profile_bindings.get")}}, wantStatus: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			principal = test.principal
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/identity/test", nil)
			for key, value := range test.pathValues {
				request.SetPathValue(key, value)
			}
			action, found := handler.actions.Definition(test.actionKey)
			if !found {
				t.Fatalf("missing test Action %q", test.actionKey)
			}
			handler.identityAction(action, next).ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d", response.Code, test.wantStatus)
			}
		})
	}
	if denials != 5 {
		t.Fatalf("security denials=%d", denials)
	}
}

func TestEffectiveMenusRejectsUnknownPrincipalAndPropagatesServiceError(t *testing.T) {
	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
	handler.principal = func(*http.Request) identitymodel.Principal { return identitymodel.Principal{} }
	handler.EffectiveMenus(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/identity/effective-menus?surface=admin_console", nil))
	if response.status != http.StatusUnauthorized {
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

func TestIdentityOrganizationUnitHandlers(t *testing.T) {
	repository := &identityHTTPRepository{organizationUnits: []identitymodel.IdentityOrganizationUnit{{ID: "organizationUnit-1", Name: "Sales"}}}
	handler, response := newIdentityHTTPHandler(repository)
	w, request := identityRoleRequest(http.MethodGet, "/identity/organization-units", "", nil)
	handler.listIdentityOrganizationUnits(w, request)
	organizationUnits, ok := response.value.([]identitymodel.IdentityOrganizationUnit)
	if response.status != http.StatusOK || !ok || len(organizationUnits) != 1 {
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
		{name: "create", call: handler.createIdentityOrganizationUnit, body: `{"id":"organizationUnit-2","code":"FINANCE","name":"Finance","node_type":"department"}`, wantStatus: http.StatusCreated, wantID: "organizationUnit-2"},
		{name: "update path id", call: handler.updateIdentityOrganizationUnit, body: `{"id":"body-id","code":"OPS","name":"Operations","node_type":"department"}`, pathValues: map[string]string{"organizationUnitID": " organizationUnit-3 "}, wantStatus: http.StatusOK, wantID: "organizationUnit-3"},
		{name: "update body id", call: handler.updateIdentityOrganizationUnit, body: `{"id":"body-id","code":"OPS","name":"Operations","node_type":"department"}`, pathValues: map[string]string{"organizationUnitID": " "}, wantStatus: http.StatusOK, wantID: "body-id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response.status, response.value, response.err = 0, nil, nil
			w, request := identityRoleRequest(http.MethodPost, "/identity/organization-units/test", test.body, test.pathValues)
			test.call(w, request)
			if response.status != test.wantStatus || repository.lastOrganizationUnit.ID != test.wantID {
				t.Fatalf("status=%d organizationUnit=%+v err=%v", response.status, repository.lastOrganizationUnit, response.err)
			}
		})
	}
}

func TestIdentityOrganizationUnitHandlersRejectDecodeAndRepositoryFailures(t *testing.T) {
	for _, call := range []func(*IdentityHandler, http.ResponseWriter, *http.Request){
		func(handler *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			handler.createIdentityOrganizationUnit(w, r)
		},
		func(handler *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			handler.updateIdentityOrganizationUnit(w, r)
		},
	} {
		repository := &identityHTTPRepository{}
		handler, response := newIdentityHTTPHandler(repository)
		w, request := identityRoleRequest(http.MethodPost, "/identity/organization-units", `{`, nil)
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
		{name: "list", repo: &identityHTTPRepository{listOrganizationUnitsErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.listIdentityOrganizationUnits(w, r)
		}},
		{name: "create", repo: &identityHTTPRepository{upsertOrganizationUnitErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.createIdentityOrganizationUnit(w, r)
		}, body: `{"id":"organizationUnit-1","code":"SALES","name":"Sales","node_type":"department"}`},
		{name: "update", repo: &identityHTTPRepository{upsertOrganizationUnitErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.updateIdentityOrganizationUnit(w, r)
		}, body: `{"id":"organizationUnit-1","code":"SALES","name":"Sales","node_type":"department"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(test.repo)
			w, request := identityRoleRequest(http.MethodPost, "/identity/organization-units", test.body, nil)
			test.call(handler, w, request)
			if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
				t.Fatalf("status=%d err=%v", response.status, response.err)
			}
		})
	}
}

func TestIdentityOrganizationUnitOwnerControlledAuthoringCurrentResource(t *testing.T) {
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
			repository: &identityHTTPRepository{listOrganizationUnitsErr: errIdentityHTTPTest},
			expected:   "empty",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "create current match",
			repository: &identityHTTPRepository{organizationUnits: []identitymodel.IdentityOrganizationUnit{{ID: "organizationUnit-1", Name: "Existing"}}},
			wantStatus: http.StatusCreated, wantUpserts: 1,
		},
		{
			name: "create current miss",
			repository: &identityHTTPRepository{
				organizationUnits:             []identitymodel.IdentityOrganizationUnit{{ID: "organizationUnit-other", Name: "Other"}},
				storeOrganizationUnitOnUpsert: true,
			},
			expected:   "empty",
			wantStatus: http.StatusCreated, wantUpserts: 1,
		},
		{
			name:       "update current load failure",
			update:     true,
			repository: &identityHTTPRepository{listOrganizationUnitsErr: errIdentityHTTPTest},
			expected:   "empty",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "update current match",
			update:     true,
			repository: &identityHTTPRepository{organizationUnits: []identitymodel.IdentityOrganizationUnit{{ID: "organizationUnit-1", Name: "Existing"}}},
			wantStatus: http.StatusOK, wantUpserts: 1,
		},
		{
			name:   "update current miss",
			update: true,
			repository: &identityHTTPRepository{
				organizationUnits:             []identitymodel.IdentityOrganizationUnit{{ID: "organizationUnit-other", Name: "Other"}},
				storeOrganizationUnitOnUpsert: true,
			},
			expected:   "empty",
			wantStatus: http.StatusOK, wantUpserts: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(test.repository)
			actionKey := "identity.organization_units.create"
			if test.update {
				actionKey = "identity.organization_units.update"
			}
			handler.principal = func(*http.Request) identitymodel.Principal {
				return identitymodel.Principal{
					Known: true, WorkspaceID: "workspace-1", UserID: "builder",
					Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, actionKey)},
				}
			}
			if test.expected == "" {
				var err error
				test.expected, err = identityAuthoringResourceHash(
					"identity.organization_unit",
					"organizationUnit-1",
					test.repository.organizationUnits[0],
					true,
				)
				if err != nil {
					t.Fatalf("resource hash: %v", err)
				}
			}
			w, request := identityRoleRequest(
				http.MethodPost,
				"/identity/organization-units/organizationUnit-1",
				`{"id":"organizationUnit-1","code":"CHANGED","name":"Changed","node_type":"department"}`,
				map[string]string{"organizationUnitID": "organizationUnit-1"},
			)
			request.Header.Set("Builder-Task-ID", "task-1")
			request.Header.Set("Idempotency-Key", "organizationUnit-"+test.name)
			request.Header.Set("Expected-Schema-Hash", test.expected)
			if test.update {
				handler.updateIdentityOrganizationUnit(w, request)
			} else {
				handler.createIdentityOrganizationUnit(w, request)
			}
			if response.status != test.wantStatus || test.repository.upsertOrganizationUnitCalls != test.wantUpserts {
				t.Fatalf("status=%d err=%v upserts=%d", response.status, response.err, test.repository.upsertOrganizationUnitCalls)
			}
		})
	}
}
