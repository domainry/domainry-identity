package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	auditapplication "github.com/domainry/domainry-identity/internal/application/audit"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityValidationAndAuditRemainingEdges(t *testing.T) {
	repository := &identityHTTPRepository{
		roles:              []identitymodel.IdentityRole{{ID: "sales_manager", Key: "sales_manager", Status: identitymodel.IdentityStatusActive}},
		menus:              []identitymodel.IdentityMenu{{ID: "orders", Key: "orders", Status: identitymodel.IdentityStatusActive}},
		failListRolesAfter: 1,
	}
	handler, response := newIdentityHTTPHandler(repository)
	_, request := identityRoleRequest(http.MethodPost, "/identity/roles/sales_manager/menus/validate", `{"menu_ids":["orders"]}`, map[string]string{"roleID": "sales_manager"})
	handler.validateIdentityRoleMenuAssignmentAuthoring(httptest.NewRecorder(), request)
	if response.status != http.StatusInternalServerError || response.err == nil {
		t.Fatalf("menu validation status=%d err=%v", response.status, response.err)
	}

	auditRepository := &identityAuthoringAuditRepository{}
	handler.audit = auditapplication.NewAuditApplicationService(auditRepository)
	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{Known: true, UserID: "auditor", WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Permissions: []string{"identity.audit.view"}}}
	}
	auditRequest := httptest.NewRequest(http.MethodPost, "/identity/audit", nil)
	handler.appendIdentityMutationAudit(auditRequest, "identity_tested", "identity_role", "role-1", "Tested identity audit", map[string]any{"source": "test"})
	if len(auditRepository.events) != 1 || auditRepository.events[0].Metadata["source"] != "test" {
		t.Fatalf("events=%+v", auditRepository.events)
	}
}

func TestIdentityRoleRemainingHandlerFailures(t *testing.T) {
	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{err: errIdentityHTTPTest})
	_, request := identityRoleRequest(http.MethodGet, "/identity/workforce/profile-1/assignable-roles", "", map[string]string{"profileID": "profile-1"})
	handler.listIdentityAssignableWorkforceRoles(httptest.NewRecorder(), request)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("assignable workforce roles err=%v", response.err)
	}

	handler, response = newIdentityHTTPHandler(&identityHTTPRepository{})
	_, request = identityRoleRequest(http.MethodGet, "/identity/workforce/profile-1/assignable-roles", "", map[string]string{"profileID": "profile-1"})
	handler.listIdentityAssignableWorkforceRoles(httptest.NewRecorder(), request)
	if response.status != http.StatusOK || response.err != nil {
		t.Fatalf("assignable workforce roles status=%d err=%v", response.status, response.err)
	}

	for _, call := range []func(http.ResponseWriter, *http.Request){handler.upsertIdentityUserWithRoles, handler.applyIdentityEntitlementBatch} {
		response.status, response.err = 0, nil
		_, malformed := identityRoleRequest(http.MethodPost, "/identity/malformed", `{`, nil)
		call(httptest.NewRecorder(), malformed)
		if response.status != http.StatusBadRequest {
			t.Fatalf("malformed status=%d err=%v", response.status, response.err)
		}
	}

	repository := &identityHTTPRepository{
		assignErr: errIdentityHTTPTest,
		users:     []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		roles:     []identitymodel.IdentityRole{{ID: "role-1", Key: "sales", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response = newIdentityHTTPHandler(repository)
	_, request = identityRoleRequest(http.MethodPost, "/identity/entitlements/batch", `{"items":[{"operation":"grant","user_id":"user-1","role_id":"role-1","reason":"job"}]}`, nil)
	request.Header.Set("Idempotency-Key", "failing-batch")
	handler.applyIdentityEntitlementBatch(httptest.NewRecorder(), request)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("entitlement err=%v", response.err)
	}
}

func TestIdentityUserCreationLookupAndSecurityFailures(t *testing.T) {
	for _, test := range []struct {
		name       string
		repository *identityHTTPRepository
		nilIssuer  bool
	}{
		{name: "lookup", repository: &identityHTTPRepository{err: errIdentityHTTPTest}},
		{name: "issuer", repository: &identityHTTPRepository{}, nilIssuer: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(test.repository)
			if test.nilIssuer {
				handler.userSecurity = nil
			}
			_, request := identityRoleRequest(http.MethodPost, "/identity/users/user-1", `{"id":"user-1","name":"User One","email":"one@example.test","status":"active"}`, nil)
			handler.createIdentityUser(httptest.NewRecorder(), request)
			if response.status != http.StatusInternalServerError {
				t.Fatalf("status=%d err=%v", response.status, response.err)
			}
		})
	}
}

func TestIdentityMenuOwnerCurrentStateEdges(t *testing.T) {
	for _, test := range []struct {
		name       string
		repository *identityHTTPRepository
		expected   string
	}{
		{name: "load failure", repository: &identityHTTPRepository{listMenusErr: errIdentityHTTPTest}, expected: "empty"},
		{name: "missing", repository: &identityHTTPRepository{menus: []identitymodel.IdentityMenu{{ID: "other", Key: "other", Status: identitymodel.IdentityStatusActive}}}, expected: "empty"},
		{name: "match", repository: &identityHTTPRepository{menus: []identitymodel.IdentityMenu{{ID: "other", Key: "other", Status: identitymodel.IdentityStatusActive}, {ID: "menu-1", Key: "orders", Status: identitymodel.IdentityStatusActive}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(test.repository)
			handler.principal = func(*http.Request) identitymodel.Principal {
				return identitymodel.Principal{Known: true, UserID: "builder", WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Permissions: []string{"identity.menus.write"}}}
			}
			if test.expected == "" {
				test.expected, _ = identityAuthoringResourceHash("identity.menu", "menu-1", test.repository.menus[len(test.repository.menus)-1], true)
			}
			_, request := identityRoleRequest(http.MethodPut, "/identity/menus/menu-1", `{"id":"menu-1","key":"orders","label":"Orders","status":"active"}`, map[string]string{"menuID": "menu-1"})
			request.Header.Set("Builder-Task-ID", "task-1")
			request.Header.Set("Idempotency-Key", "menu-"+test.name)
			request.Header.Set("Expected-Schema-Hash", test.expected)
			handler.upsertIdentityMenu(httptest.NewRecorder(), request)
			if test.name == "load failure" && response.err != errIdentityHTTPTest {
				t.Fatalf("load err=%v", response.err)
			}
		})
	}
}

func TestIdentityWorkforceRemainingReadAndCurrentEdges(t *testing.T) {
	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{err: errIdentityHTTPTest})
	_, projection := identityRoleRequest(http.MethodGet, "/identity/workforce?projection=application", "", nil)
	handler.listIdentityWorkforceProfiles(httptest.NewRecorder(), projection)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("projection err=%v", response.err)
	}

	handler, response = newIdentityHTTPHandler(&identityHTTPRepository{})
	_, missing := identityRoleRequest(http.MethodGet, "/identity/workforce/missing/assignments", "", map[string]string{"profileID": "missing"})
	handler.listIdentityWorkforceAssignments(httptest.NewRecorder(), missing)
	if response.status != http.StatusNotFound {
		t.Fatalf("missing status=%d err=%v", response.status, response.err)
	}

	repository := &identityHTTPRepository{
		workforceProfiles:                 []identitymodel.IdentityWorkforceProfile{{ID: "profile-1", WorkStatus: identitymodel.IdentityWorkActive}},
		failListWorkforceAssignmentsAfter: 1,
	}
	handler, response = newIdentityHTTPHandler(repository)
	_, list := identityRoleRequest(http.MethodGet, "/identity/workforce/profile-1/assignments", "", map[string]string{"profileID": "profile-1"})
	handler.listIdentityWorkforceAssignments(httptest.NewRecorder(), list)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("assignment list err=%v", response.err)
	}
	repository.failListWorkforceAssignmentsAfter = 0
	repository.listWorkforceAssignmentsErr = errIdentityHTTPTest

	successRepository := &identityHTTPRepository{
		workforceProfiles:    []identitymodel.IdentityWorkforceProfile{{ID: "profile-1", WorkStatus: identitymodel.IdentityWorkActive}},
		workforceAssignments: []identitymodel.IdentityWorkforceAssignment{{ID: "assignment-1", WorkforceProfileID: "profile-1"}},
	}
	successHandler, successResponse := newIdentityHTTPHandler(successRepository)
	_, successfulList := identityRoleRequest(http.MethodGet, "/identity/workforce/profile-1/assignments", "", map[string]string{"profileID": "profile-1"})
	successHandler.listIdentityWorkforceAssignments(httptest.NewRecorder(), successfulList)
	if successResponse.status != http.StatusOK || successResponse.err != nil {
		t.Fatalf("assignment list status=%d err=%v", successResponse.status, successResponse.err)
	}

	queryRequest := httptest.NewRequest(http.MethodGet, "/identity/workforce?page_size=500", nil)
	if query := identityWorkforceProjectionQuery(queryRequest); query.PageSize != 200 {
		t.Fatalf("page size=%d", query.PageSize)
	}

	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{Known: true, UserID: "builder", WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Permissions: []string{"identity.workforce.write"}}}
	}
	_, upsert := identityRoleRequest(http.MethodPut, "/identity/workforce/profile-1/assignments/assignment-1", `{"id":"assignment-1","workforce_profile_id":"profile-1","organization_unit_id":"sales","assignment_type":"primary","status":"active"}`, map[string]string{"profileID": "profile-1"})
	upsert.Header.Set("Builder-Task-ID", "task-1")
	upsert.Header.Set("Idempotency-Key", "assignment-1")
	upsert.Header.Set("Expected-Schema-Hash", "empty")
	handler.upsertIdentityWorkforceAssignment(httptest.NewRecorder(), upsert)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("assignment current err=%v", response.err)
	}

	successHandler.principal = handler.principal
	expected, _ := identityAuthoringResourceHash("identity.workforce_assignment", "profile-1", successRepository.workforceAssignments, true)
	_, successfulUpsert := identityRoleRequest(http.MethodPut, "/identity/workforce/profile-1/assignments/assignment-2", `{"id":"assignment-2","workforce_profile_id":"profile-1","organization_unit_id":"sales","assignment_type":"secondary","status":"active"}`, map[string]string{"profileID": "profile-1"})
	successfulUpsert.Header.Set("Builder-Task-ID", "task-1")
	successfulUpsert.Header.Set("Idempotency-Key", "assignment-2")
	successfulUpsert.Header.Set("Expected-Schema-Hash", expected)
	successHandler.upsertIdentityWorkforceAssignment(httptest.NewRecorder(), successfulUpsert)
	if successResponse.status != http.StatusOK || successResponse.err != nil {
		t.Fatalf("assignment current success status=%d err=%v", successResponse.status, successResponse.err)
	}
}

func TestIdentityRoleAndMenuOwnerCurrentCallbacks(t *testing.T) {
	repository := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{{ID: "role-1", Key: "role-1", Status: identitymodel.IdentityStatusActive}},
		menus: []identitymodel.IdentityMenu{{ID: "orders", Key: "orders", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{Known: true, UserID: "builder", WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Permissions: []string{"identity.roles.write", "identity.menus.write"}}}
	}
	_, assign := identityRoleRequest(http.MethodPost, "/identity/users/user-1/roles", `{"role_id":"role-1"}`, map[string]string{"userID": "user-1"})
	assign.Header.Set("Builder-Task-ID", "task-1")
	assign.Header.Set("Idempotency-Key", "assign-role-1")
	assign.Header.Set("Expected-Schema-Hash", "empty")
	handler.assignIdentityUserRole(httptest.NewRecorder(), assign)
	if response.status != http.StatusCreated || response.err != nil {
		t.Fatalf("assign status=%d err=%v", response.status, response.err)
	}

	response.status, response.value, response.err = 0, nil, nil
	_, menus := identityRoleRequest(http.MethodPut, "/identity/roles/role-1/menus", `{"menu_ids":["orders"]}`, map[string]string{"roleID": "role-1"})
	menus.Header.Set("Builder-Task-ID", "task-1")
	menus.Header.Set("Idempotency-Key", "role-1-menus")
	menus.Header.Set("Expected-Schema-Hash", "empty")
	handler.setIdentityRoleMenus(httptest.NewRecorder(), menus)
	if response.status != http.StatusOK || response.err != nil {
		t.Fatalf("menus status=%d err=%v", response.status, response.err)
	}
}
