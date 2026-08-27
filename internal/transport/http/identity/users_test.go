package identity

import (
	"net/http"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityUserReadHandlers(t *testing.T) {
	repository := &identityHTTPRepository{users: []identitymodel.IdentityUser{{ID: "user-1", Email: "one@example.test", Status: identitymodel.IdentityStatusActive}}}
	handler, response := newIdentityHTTPHandler(repository)

	w, request := identityRoleRequest(http.MethodGet, "/identity/users", "", nil)
	handler.listIdentityUsers(w, request)
	users, ok := response.value.([]identitymodel.IdentityUser)
	if response.status != http.StatusOK || !ok || len(users) != 1 {
		t.Fatalf("list status=%d value=%#v err=%v", response.status, response.value, response.err)
	}

	response.status, response.value, response.err = 0, nil, nil
	w, request = identityRoleRequest(http.MethodGet, "/identity/users/user-1", "", map[string]string{"userID": " user-1 "})
	handler.getIdentityUser(w, request)
	user, ok := response.value.(identitymodel.IdentityUser)
	if response.status != http.StatusOK || !ok || user.ID != "user-1" {
		t.Fatalf("get status=%d value=%#v err=%v", response.status, response.value, response.err)
	}
	if resourceHash := w.Header().Get(identityResourceHashHeader); resourceHash == "" || resourceHash == "empty" {
		t.Fatalf("get resource hash=%q", resourceHash)
	}

	response.status, response.value, response.err = 0, nil, nil
	w, request = identityRoleRequest(http.MethodGet, "/identity/users/missing", "", map[string]string{"userID": "missing"})
	handler.getIdentityUser(w, request)
	if response.status != http.StatusNotFound || response.err != nil {
		t.Fatalf("missing status=%d err=%v", response.status, response.err)
	}

	repository.err = errIdentityHTTPTest
	for _, call := range []func(http.ResponseWriter, *http.Request){handler.listIdentityUsers, handler.getIdentityUser} {
		response.status, response.value, response.err = 0, nil, nil
		call(w, request)
		if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
			t.Fatalf("service failure status=%d err=%v", response.status, response.err)
		}
	}
}

func TestIdentityUserMutationHandlers(t *testing.T) {
	tests := []struct {
		name       string
		call       func(*IdentityHandler, http.ResponseWriter, *http.Request)
		method     string
		body       string
		path       map[string]string
		wantStatus int
		wantID     string
		wantState  identitymodel.IdentityStatus
	}{
		{name: "create", call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.createIdentityUser(w, r) }, method: http.MethodPost, body: `{"id":"user-1","name":"User One","email":"one@example.test","status":"active"}`, wantStatus: http.StatusCreated, wantID: "user-1"},
		{name: "update path id", call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.updateIdentityUser(w, r) }, method: http.MethodPatch, body: `{"id":"body-id","name":"User One","email":"one@example.test"}`, path: map[string]string{"userID": " user-2 "}, wantStatus: http.StatusOK, wantID: "user-2"},
		{name: "update body id", call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.updateIdentityUser(w, r) }, method: http.MethodPatch, body: `{"id":"body-id","name":"User One","email":"one@example.test"}`, path: map[string]string{"userID": " "}, wantStatus: http.StatusOK, wantID: "body-id"},
		{name: "disable", call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.disableIdentityUser(w, r) }, method: http.MethodPost, path: map[string]string{"userID": " user-3 "}, wantStatus: http.StatusNoContent, wantID: "user-3", wantState: identitymodel.IdentityStatusDisabled},
		{name: "enable", call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.enableIdentityUser(w, r) }, method: http.MethodPost, path: map[string]string{"userID": " user-3 "}, wantStatus: http.StatusNoContent, wantID: "user-3", wantState: identitymodel.IdentityStatusActive},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &identityHTTPRepository{}
			handler, response := newIdentityHTTPHandler(repository)
			response.status, response.value, response.err = 0, nil, nil
			w, request := identityRoleRequest(test.method, "/identity/users/test", test.body, test.path)
			test.call(handler, w, request)
			status := response.status
			if test.wantStatus == http.StatusNoContent {
				status = w.Code
			}
			if status != test.wantStatus || response.err != nil {
				t.Fatalf("status=%d callback=%d err=%v", status, response.status, response.err)
			}
			if test.wantState == "" {
				if repository.lastUser.ID != test.wantID {
					t.Fatalf("user=%+v want id=%q", repository.lastUser, test.wantID)
				}
			} else if repository.lastUserID != test.wantID || repository.lastStatus != test.wantState {
				t.Fatalf("user id=%q status=%q", repository.lastUserID, repository.lastStatus)
			}
		})
	}
}

func TestCreateIdentityUserIssuesOneTimeInitialCredential(t *testing.T) {
	repository := &identityHTTPRepository{}
	handler, response := newIdentityHTTPHandler(repository)
	security := handler.userSecurity.(*identityHTTPUserSecurity)
	security.initialPassword = "Vd!9random-initial-password"
	w, request := identityRoleRequest(
		http.MethodPost,
		"/identity/users",
		`{"id":"user-1","name":"User One","email":"one@example.test","status":"active"}`,
		nil,
	)

	handler.createIdentityUser(w, request)

	result, ok := response.value.(identityUserProvisioningResponse)
	if response.status != http.StatusCreated || response.err != nil || !ok {
		t.Fatalf("status=%d value=%#v err=%v", response.status, response.value, response.err)
	}
	if result.ID != "user-1" || result.InitialPassword != security.initialPassword || !result.MustChangePassword {
		t.Fatalf("provisioning response=%#v", result)
	}
	if security.issuedUserID != "user-1" {
		t.Fatalf("issued user=%q", security.issuedUserID)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("credential response cache policy=%v", w.Header())
	}
}

func TestCreateIdentityUserRejectsExistingAccountWithoutRotatingCredential(t *testing.T) {
	repository := &identityHTTPRepository{users: []identitymodel.IdentityUser{{
		ID: "user-1", Name: "Existing User", Email: "existing@example.test", Status: identitymodel.IdentityStatusActive,
	}}}
	handler, response := newIdentityHTTPHandler(repository)
	security := handler.userSecurity.(*identityHTTPUserSecurity)
	w, request := identityRoleRequest(
		http.MethodPost,
		"/identity/users",
		`{"id":"user-1","name":"Replacement","email":"replacement@example.test","status":"active"}`,
		nil,
	)

	handler.createIdentityUser(w, request)

	if response.status != http.StatusConflict || apperror.CodeOf(response.err) != "backend.identity.user_already_exists" {
		t.Fatalf("status=%d err=%v", response.status, response.err)
	}
	if security.issuedUserID != "" || repository.upsertUserCalls != 0 {
		t.Fatalf("credential rotated or user overwritten: issued=%q upserts=%d", security.issuedUserID, repository.upsertUserCalls)
	}
}

func TestCreateIdentityUserRollsBackWhenCredentialIssueFails(t *testing.T) {
	repository := &identityHTTPRepository{}
	handler, response := newIdentityHTTPHandler(repository)
	handler.userSecurity = &identityHTTPUserSecurity{err: errIdentityHTTPTest}
	w, request := identityRoleRequest(
		http.MethodPost,
		"/identity/users",
		`{"id":"user-1","name":"User One","email":"one@example.test","status":"active"}`,
		nil,
	)

	handler.createIdentityUser(w, request)

	if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
		t.Fatalf("status=%d err=%v", response.status, response.err)
	}
	if repository.removeUserCalls != 1 || repository.lastUserID != "user-1" {
		t.Fatalf("rollback calls=%d user=%q", repository.removeUserCalls, repository.lastUserID)
	}
}

func TestIdentityUserMutationHandlersRejectInvalidJSONAndServiceFailures(t *testing.T) {
	for _, callName := range []string{"create", "update"} {
		repository := &identityHTTPRepository{}
		handler, response := newIdentityHTTPHandler(repository)
		w, request := identityRoleRequest(http.MethodPost, "/identity/users", `{`, map[string]string{"userID": "user-1"})
		if callName == "create" {
			handler.createIdentityUser(w, request)
		} else {
			handler.updateIdentityUser(w, request)
		}
		if response.status != http.StatusBadRequest {
			t.Fatalf("%s invalid JSON status=%d", callName, response.status)
		}
	}

	tests := []struct {
		name string
		repo *identityHTTPRepository
		call func(*IdentityHandler, http.ResponseWriter, *http.Request)
		body string
	}{
		{name: "create", repo: &identityHTTPRepository{upsertUserErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.createIdentityUser(w, r) }, body: `{"id":"user-1","name":"User One","email":"one@example.test"}`},
		{name: "update", repo: &identityHTTPRepository{upsertUserErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.updateIdentityUser(w, r) }, body: `{"id":"user-1","name":"User One","email":"one@example.test"}`},
		{name: "disable", repo: &identityHTTPRepository{statusErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.disableIdentityUser(w, r) }},
		{name: "enable", repo: &identityHTTPRepository{statusErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.enableIdentityUser(w, r) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(test.repo)
			w, request := identityRoleRequest(http.MethodPost, "/identity/users/user-1", test.body, map[string]string{"userID": "user-1"})
			test.call(handler, w, request)
			if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
				t.Fatalf("status=%d err=%v", response.status, response.err)
			}
		})
	}
}

func TestIdentityUserMutationHandlersForwardPostWriteReadFailures(t *testing.T) {
	tests := []struct {
		name string
		repo *identityHTTPRepository
		call func(*IdentityHandler, http.ResponseWriter, *http.Request)
	}{
		{
			name: "create read error",
			repo: &identityHTTPRepository{listUsersErrAfterUpsert: errIdentityHTTPTest},
			call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.createIdentityUser(w, r) },
		},
		{
			name: "create missing persisted user",
			repo: &identityHTTPRepository{dropUpsertUser: true},
			call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.createIdentityUser(w, r) },
		},
		{
			name: "update read error",
			repo: &identityHTTPRepository{listUsersErrAfterUpsert: errIdentityHTTPTest},
			call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.updateIdentityUser(w, r) },
		},
		{
			name: "update missing persisted user",
			repo: &identityHTTPRepository{dropUpsertUser: true},
			call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.updateIdentityUser(w, r) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(test.repo)
			w, request := identityRoleRequest(
				http.MethodPost,
				"/identity/users/user-1",
				`{"id":"user-1","name":"User One","email":"one@example.test","status":"active"}`,
				map[string]string{"userID": "user-1"},
			)
			test.call(handler, w, request)
			if response.status != http.StatusInternalServerError {
				t.Fatalf("status=%d err=%v value=%#v", response.status, response.err, response.value)
			}
		})
	}
}

func TestUpdateIdentityUserUsesCurrentResourceForOwnerControlledAuthoring(t *testing.T) {
	repository := &identityHTTPRepository{}
	handler, response := newIdentityHTTPHandler(repository)
	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{
			Known: true, WorkspaceID: "workspace-1", UserID: "builder",
			Role: identitymodel.RoleSchema{Permissions: []string{"identity.users.write"}},
		}
	}
	w, request := identityRoleRequest(
		http.MethodPatch,
		"/identity/users/user-1",
		`{"id":"user-1","name":"User One","email":"one@example.test","status":"active"}`,
		map[string]string{"userID": "user-1"},
	)
	request.Header.Set("Builder-Task-ID", "task-1")
	request.Header.Set("Idempotency-Key", "update-user-1")
	request.Header.Set("Expected-Schema-Hash", "empty")
	handler.updateIdentityUser(w, request)
	if response.status != http.StatusOK || response.err != nil || repository.upsertUserCalls != 1 {
		t.Fatalf("status=%d err=%v value=%#v upserts=%d", response.status, response.err, response.value, repository.upsertUserCalls)
	}
}

func TestDeleteIdentityUserWithoutProfileReferences(t *testing.T) {
	for _, test := range []struct {
		name      string
		removeErr error
		wantCode  int
	}{
		{name: "success", wantCode: http.StatusNoContent},
		{name: "repository failure", removeErr: errIdentityHTTPTest, wantCode: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &identityHTTPRepository{
				removeUserErr: test.removeErr,
				users:         []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
			}
			handler, response := newIdentityHTTPHandler(repository)
			handler.principal = func(*http.Request) identitymodel.Principal {
				return identitymodel.Principal{Known: true, WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Permissions: []string{"workspace.admin"}, RecordScope: "all_records"}}
			}
			w, request := identityRoleRequest(http.MethodDelete, "/identity/users/user-1", "", map[string]string{"userID": " user-1 "})
			handler.deleteIdentityUser(w, request)
			status := response.status
			if test.wantCode == http.StatusNoContent {
				status = w.Code
			}
			if status != test.wantCode || repository.lastUserID != "user-1" {
				t.Fatalf("status=%d callback=%d user=%q err=%v", status, response.status, repository.lastUserID, response.err)
			}
		})
	}
}

func TestDisableIdentityUserRevokesSessionsAndPreservesBusinessIdentities(t *testing.T) {
	repository := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{{
			ID: "worker-1", IdentityUserID: "user-1", WorkStatus: identitymodel.IdentityWorkActive,
		}},
		profileBindings: []identitymodel.IdentityProfileBinding{{
			IdentityUserID: "user-1", ObjectKey: "member_profile", ProfileID: "member-1", Status: identitymodel.IdentityProfileBindingActive,
		}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	security := handler.userSecurity.(*identityHTTPUserSecurity)
	writer, request := identityRoleRequest(http.MethodPost, "/identity/users/user-1/disable", "", map[string]string{"userID": "user-1"})
	handler.disableIdentityUser(writer, request)
	if writer.Code != http.StatusNoContent || response.err != nil || security.revoked != 1 {
		t.Fatalf("status=%d revoked=%d err=%v", writer.Code, security.revoked, response.err)
	}
	if repository.workforceProfiles[0].WorkStatus != identitymodel.IdentityWorkActive ||
		repository.profileBindings[0].Status != identitymodel.IdentityProfileBindingActive {
		t.Fatalf("business identities changed: workforce=%#v profiles=%#v", repository.workforceProfiles, repository.profileBindings)
	}
}

func TestDisableIdentityUserReportsSessionRevocationAvailabilityAndFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		security IdentityUserSecurity
		wantCode int
	}{
		{"unavailable", nil, http.StatusServiceUnavailable},
		{"failure", &identityHTTPUserSecurity{err: errIdentityHTTPTest}, http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &identityHTTPRepository{users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}}}
			handler, response := newIdentityHTTPHandler(repository)
			handler.userSecurity = test.security
			writer, request := identityRoleRequest(http.MethodPost, "/identity/users/user-1/disable", "", map[string]string{"userID": "user-1"})
			handler.disableIdentityUser(writer, request)
			if response.status != test.wantCode {
				t.Fatalf("status=%d want=%d err=%v", response.status, test.wantCode, response.err)
			}
		})
	}
}

func TestRevokeIdentityUserMFAFactor(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		wantCode int
	}{
		{name: "success", wantCode: http.StatusOK},
		{name: "failure", err: errIdentityHTTPTest, wantCode: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
			security := handler.userSecurity.(*identityHTTPUserSecurity)
			security.err = test.err
			writer, request := identityRoleRequest(http.MethodDelete, "/identity/users/user-1/mfa/factor-1", "", map[string]string{"userID": "user-1", "factorID": "factor-1"})
			handler.revokeIdentityUserMFAFactor(writer, request)
			if response.status != test.wantCode {
				t.Fatalf("status=%d want=%d err=%v", response.status, test.wantCode, response.err)
			}
			if security.revokedFactorID != "factor-1" {
				t.Fatalf("factor id=%q", security.revokedFactorID)
			}
		})
	}
}

func TestDeleteIdentityUserProfileReferenceBoundaries(t *testing.T) {
	for _, test := range []struct {
		name         string
		total        int
		referenceErr error
		wantCode     int
	}{
		{name: "profile reference blocks delete", total: 2, wantCode: http.StatusConflict},
		{name: "profile reference lookup failure", referenceErr: errIdentityHTTPTest, wantCode: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &identityHTTPRepository{}
			inspection := identityapplication.IdentityUserDeletionInspection{}
			if test.total > 0 {
				inspection.BusinessProfileReferences = []identitymodel.IdentityUserRecordReference{{ObjectKey: "member_profile", FieldKey: "identity_user", Count: test.total}}
			}
			handler, response := newIdentityHTTPHandler(repository, &identityHTTPDeletionInspector{inspection: inspection, err: test.referenceErr})
			repository.users = []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}}
			w, request := identityRoleRequest(http.MethodDelete, "/identity/users/user-1", "", map[string]string{"userID": " user-1 "})
			handler.deleteIdentityUser(w, request)
			if response.status != test.wantCode || repository.removeUserCalls != 0 {
				t.Fatalf("status=%d remove calls=%d err=%v", response.status, repository.removeUserCalls, response.err)
			}
			if test.referenceErr != nil && response.err == nil {
				t.Fatal("reference lookup failure was not propagated")
			}
		})
	}
}

func TestIdentityUserDeletionImpactHandler(t *testing.T) {
	repository := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		profileBindings: []identitymodel.IdentityProfileBinding{{
			IdentityUserID: "user-1", ObjectKey: "member_profile", ProfileID: "member-1", Status: identitymodel.IdentityProfileBindingActive,
		}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "member", Status: "active"}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	w, request := identityRoleRequest(http.MethodGet, "/identity/users/user-1/deletion-impact", "", map[string]string{"userID": " user-1 "})
	handler.getIdentityUserDeletionImpact(w, request)
	impact, ok := response.value.(identitymodel.IdentityUserDeletionImpact)
	if response.status != http.StatusOK || !ok || impact.CanDelete || len(impact.ProfileBindings) != 1 || len(impact.ActiveRoleIDs) != 1 {
		t.Fatalf("response=%+v impact=%+v", response, impact)
	}
}

func TestIdentityUserDisableImpactHandler(t *testing.T) {
	repository := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		profileBindings: []identitymodel.IdentityProfileBinding{{
			IdentityUserID: "user-1", BindingKey: "member", ObjectKey: "member_profile", ProfileID: "member-1", Status: identitymodel.IdentityProfileBindingActive,
		}},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{{ID: "workforce-1", IdentityUserID: "user-1", WorkStatus: identitymodel.IdentityWorkActive}},
		assignments:       []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "member", Status: "active"}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	w, request := identityRoleRequest(http.MethodGet, "/identity/users/user-1/disable-impact", "", map[string]string{"userID": " user-1 "})
	handler.getIdentityUserDisableImpact(w, request)
	impact, ok := response.value.(identitymodel.IdentityUserDisableImpact)
	if response.status != http.StatusOK || !ok || len(impact.ProfileBindings) != 1 || len(impact.WorkforceProfileIDs) != 1 || len(impact.ActiveEntitlementRoleIDs) != 1 || !impact.SessionsWillBeRevoked || !impact.BusinessFactsPreserved {
		t.Fatalf("response=%+v impact=%+v", response, impact)
	}
}

func TestIdentityUserImpactHandlersForwardServiceErrors(t *testing.T) {
	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{err: errIdentityHTTPTest})
	for _, call := range []func(http.ResponseWriter, *http.Request){
		handler.getIdentityUserDeletionImpact,
		handler.getIdentityUserDisableImpact,
	} {
		response.status, response.value, response.err = 0, nil, nil
		w, request := identityRoleRequest(http.MethodGet, "/identity/users/user-1/impact", "", map[string]string{"userID": "user-1"})
		call(w, request)
		if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
			t.Fatalf("status=%d err=%v", response.status, response.err)
		}
	}
}
