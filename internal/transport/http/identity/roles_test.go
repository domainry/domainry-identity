package identity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func identityRoleRequest(method, target, body string, pathValues map[string]string) (*httptest.ResponseRecorder, *http.Request) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request = request.WithContext(requestcontext.WithWorkspaceID(request.Context(), "workspace-1"))
	for key, value := range pathValues {
		request.SetPathValue(key, value)
	}
	return recorder, request
}

func TestIdentityRoleReadHandlers(t *testing.T) {
	repo := &identityHTTPRepository{
		users:       []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		roles:       []identitymodel.IdentityRole{{ID: "role-1", Key: "sales", Label: "Sales"}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "role-1"}},
		requests:    []identitymodel.IdentityRoleRequest{{ID: "request-1", UserID: "user-1", Status: "pending"}},
	}
	handler, response := newIdentityHTTPHandler(repo)

	tests := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		url  string
		path map[string]string
	}{
		{name: "list roles", call: handler.listIdentityRoles, url: "/identity/roles"},
		{name: "search roles", call: handler.searchIdentityRoles, url: "/identity/roles/search?page=2&page_size=5&search=sales&search_fields=label,%20key,,"},
		{name: "role governance detail", call: handler.getIdentityRoleGovernanceDetail, url: "/identity/roles/role-1/governance-detail", path: map[string]string{"roleID": " role-1 "}},
		{name: "list assignments", call: handler.listIdentityUserRoleAssignments, url: "/identity/users/user-1/role-assignments", path: map[string]string{"userID": " user-1 "}},
		{name: "list assignable roles", call: handler.listIdentityAssignableRoles, url: "/identity/users/user-1/assignable-roles", path: map[string]string{"userID": " user-1 "}},
		{name: "list requests", call: handler.listIdentityRoleRequests, url: "/identity/role-requests?status=%20pending%20&user_id=%20user-1%20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response.status, response.err, response.value = 0, nil, nil
			w, request := identityRoleRequest(http.MethodGet, tt.url, "", tt.path)
			tt.call(w, request)
			if response.status != http.StatusOK || response.err != nil || response.value == nil {
				t.Fatalf("response = status %d value %#v err %v", response.status, response.value, response.err)
			}
		})
	}
	if repo.lastUserID != "user-1" {
		t.Fatalf("trimmed user id = %q", repo.lastUserID)
	}
	w, request := identityRoleRequest(http.MethodGet, "/identity/users/user-1/role-assignments", "", map[string]string{"userID": "user-1"})
	handler.listIdentityUserRoleAssignments(w, request)
	if got := w.Header().Get(identityResourceHashHeader); got == "" || got == "empty" {
		t.Fatalf("assignment resource hash = %q", got)
	}
	repo.assignments = nil
	w, request = identityRoleRequest(http.MethodGet, "/identity/users/user-1/role-assignments", "", map[string]string{"userID": "user-1"})
	handler.listIdentityUserRoleAssignments(w, request)
	if got := w.Header().Get(identityResourceHashHeader); got != "empty" {
		t.Fatalf("empty assignment resource hash = %q", got)
	}

	repo.err = errIdentityHTTPTest
	response.status, response.err = 0, nil
	w, request = identityRoleRequest(http.MethodGet, "/identity/roles", "", nil)
	handler.listIdentityRoles(w, request)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("service error = %v", response.err)
	}
	response.status, response.err = 0, nil
	handler.searchIdentityRoles(w, request)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("search service error = %v", response.err)
	}
	response.status, response.err = 0, nil
	_, governanceRequest := identityRoleRequest(http.MethodGet, "/identity/roles/role-1/governance-detail", "", map[string]string{"roleID": "role-1"})
	handler.getIdentityRoleGovernanceDetail(w, governanceRequest)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("governance detail service error = %v", response.err)
	}
	response.status, response.err = 0, nil
	handler.listIdentityUserRoleAssignments(w, request)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("assignment service error = %v", response.err)
	}
	response.status, response.err = 0, nil
	_, assignableRequest := identityRoleRequest(http.MethodGet, "/identity/users/user-1/assignable-roles", "", map[string]string{"userID": "user-1"})
	handler.listIdentityAssignableRoles(w, assignableRequest)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("assignable role service error = %v", response.err)
	}
	response.status, response.err = 0, nil
	handler.listIdentityRoleRequests(w, request)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("request service error = %v", response.err)
	}
}

func TestIdentityRoleAssignmentMutationHandlers(t *testing.T) {
	repo := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{{ID: "role-1", Key: "sales", Label: "Sales", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response := newIdentityHTTPHandler(repo)
	tests := []struct {
		name       string
		call       func(http.ResponseWriter, *http.Request)
		method     string
		body       string
		path       map[string]string
		wantStatus int
	}{
		{name: "assign", call: handler.assignIdentityUserRole, method: http.MethodPost, body: `{"role_id":" role-1 "}`, path: map[string]string{"userID": " user-1 "}, wantStatus: http.StatusCreated},
		{name: "remove assignment", call: handler.removeIdentityUserRole, method: http.MethodDelete, path: map[string]string{"userID": " user-1 ", "roleID": " role-1 "}, wantStatus: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response.status, response.err, response.value = 0, nil, nil
			w, request := identityRoleRequest(tt.method, "/identity/test", tt.body, tt.path)
			tt.call(w, request)
			status := response.status
			if tt.wantStatus == http.StatusNoContent {
				status = w.Code
			}
			if status != tt.wantStatus || response.err != nil {
				t.Fatalf("response = status %d callback %d err %v", status, response.status, response.err)
			}
		})
	}
	if repo.lastUserID != "user-1" || repo.lastRoleID != "role-1" {
		t.Fatalf("assignment ids = user %q role %q", repo.lastUserID, repo.lastRoleID)
	}
}

func TestIdentityUserRoleAtomicReconcileHandler(t *testing.T) {
	repo := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Email: "old@example.com", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{{ID: "role-1", Key: "sales", Label: "Sales", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response := newIdentityHTTPHandler(repo)
	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{Known: true, UserID: "admin", Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.user_role_assignments.account_and_roles_update")}}
	}
	w, request := identityRoleRequest(http.MethodPut, "/identity/users/user-1/account-and-roles",
		`{"user":{"name":"Updated","email":"updated@example.com","status":"active"},"assignments":[{"role_id":"role-1"}]}`,
		map[string]string{"userID": " user-1 "})
	handler.upsertIdentityUserWithRoles(w, request)
	if response.status != http.StatusOK || response.err != nil || repo.lastUser.ID != "user-1" ||
		len(repo.assignments) != 1 || repo.assignments[0].UserID != "user-1" {
		t.Fatalf("response=%+v user=%+v assignments=%+v", response, repo.lastUser, repo.assignments)
	}
	repo.assignErr = errIdentityHTTPTest
	response.status, response.err = 0, nil
	_, request = identityRoleRequest(http.MethodPut, "/identity/users/user-1/account-and-roles",
		`{"user":{"name":"Updated","email":"updated@example.com","status":"active"},"assignments":[{"role_id":"role-1"}]}`,
		map[string]string{"userID": "user-1"})
	handler.upsertIdentityUserWithRoles(w, request)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("service error=%v", response.err)
	}
}

func TestIdentityEntitlementBatchHandler(t *testing.T) {
	repo := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{{ID: "role-1", Key: "sales", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response := newIdentityHTTPHandler(repo)
	w, request := identityRoleRequest(http.MethodPost, "/identity/entitlements/batch", `{"items":[{"operation":"grant","user_id":"user-1","role_id":"role-1","reason":"job"}]}`, nil)
	request.Header.Set("Idempotency-Key", "batch-1")
	handler.applyIdentityEntitlementBatch(w, request)
	receipt, ok := response.value.(identitymodel.IdentityEntitlementBatchReceipt)
	if response.status != http.StatusOK || !ok || receipt.ID == "" || len(repo.assignments) != 1 {
		t.Fatalf("response status=%d value=%#v assignments=%#v err=%v", response.status, response.value, repo.assignments, response.err)
	}
}

func TestIdentityRoleRequestDecisionHandlers(t *testing.T) {
	for _, decision := range []struct {
		name string
		call func(*IdentityHandler, http.ResponseWriter, *http.Request)
		want string
	}{
		{name: "approve", call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.approveIdentityRoleRequest(w, r) }, want: "approved"},
		{name: "reject", call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.rejectIdentityRoleRequest(w, r) }, want: "rejected"},
	} {
		t.Run(decision.name, func(t *testing.T) {
			repo := &identityHTTPRepository{
				users:    []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
				roles:    []identitymodel.IdentityRole{{ID: "role-1", Status: identitymodel.IdentityStatusActive}},
				requests: []identitymodel.IdentityRoleRequest{{ID: "request-1", UserID: "user-1", RoleIDs: []string{"role-1"}, Status: "pending"}},
			}
			handler, response := newIdentityHTTPHandler(repo)
			w, request := identityRoleRequest(http.MethodPost, "/identity/role-requests/request-1/"+decision.name, `{"note":" reviewed "}`, map[string]string{"requestID": " request-1 "})
			decision.call(handler, w, request)
			got, ok := response.value.(identitymodel.IdentityRoleRequest)
			if response.status != http.StatusOK || !ok || got.Status != decision.want || got.ReviewedBy != "reviewer-1" || got.ReviewNote != "reviewed" {
				t.Fatalf("response = status %d value %#v err %v", response.status, response.value, response.err)
			}
		})
	}
}

func TestIdentityRoleHandlersRejectInvalidJSON(t *testing.T) {
	repo := &identityHTTPRepository{}
	handler, response := newIdentityHTTPHandler(repo)
	for _, call := range []func(http.ResponseWriter, *http.Request){handler.assignIdentityUserRole} {
		response.status, response.err = 0, nil
		w, request := identityRoleRequest(http.MethodPost, "/identity/test", `{`, nil)
		call(w, request)
		if response.status != http.StatusBadRequest {
			t.Fatalf("invalid JSON status = %d", response.status)
		}
	}
	for _, call := range []func(http.ResponseWriter, *http.Request){handler.approveIdentityRoleRequest, handler.rejectIdentityRoleRequest} {
		response.status, response.err = 0, nil
		w, request := identityRoleRequest(http.MethodPost, "/identity/test", `{`, nil)
		call(w, request)
		if response.status != http.StatusBadRequest {
			t.Fatalf("invalid decision JSON status = %d", response.status)
		}
	}
}

func TestIdentityRoleMutationServiceErrors(t *testing.T) {
	tests := []struct {
		name string
		repo *identityHTTPRepository
		call func(*IdentityHandler, http.ResponseWriter, *http.Request)
		body string
		path map[string]string
	}{
		{name: "assign", repo: &identityHTTPRepository{users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}}, roles: []identitymodel.IdentityRole{{ID: "role-1", Status: identitymodel.IdentityStatusActive}}, assignErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.assignIdentityUserRole(w, r) }, body: `{"role_id":"role-1"}`, path: map[string]string{"userID": "user-1"}},
		{name: "remove assignment", repo: &identityHTTPRepository{removeAssignmentErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.removeIdentityUserRole(w, r) }, path: map[string]string{"userID": "user-1", "roleID": "role-1"}},
		{name: "approve", repo: &identityHTTPRepository{}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.approveIdentityRoleRequest(w, r) }, path: map[string]string{"requestID": "missing"}},
		{name: "reject", repo: &identityHTTPRepository{}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.rejectIdentityRoleRequest(w, r) }, path: map[string]string{"requestID": "missing"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(tt.repo)
			w, request := identityRoleRequest(http.MethodPost, "/identity/test", tt.body, tt.path)
			tt.call(handler, w, request)
			if response.err == nil || response.status != http.StatusInternalServerError {
				t.Fatalf("response = status %d err %v", response.status, response.err)
			}
		})
	}
}
