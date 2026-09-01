package identity

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityWorkforceAuthoringUsesGovernedIdempotencyReceipt(t *testing.T) {
	repository := &identityHTTPRepository{users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}}}
	handler, response := newIdentityHTTPHandler(repository)
	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{
			Known: true, WorkspaceID: "workspace-1", UserID: "hr-1",
			Role: identitymodel.RoleSchema{Permissions: []string{"identity.workforce.create"}},
		}
	}
	request := workforceRequest(http.MethodPost, "/identity/workforce", []byte(`{"id":"workforce-1","organization_id":"organization-1","identity_user_id":"user-1","worker_no":"E-001","worker_type":"employee","work_status":"active"}`))
	request.Header.Set("Builder-Task-ID", "task-1")
	request.Header.Set("Idempotency-Key", "create-workforce-1")
	request.Header.Set("Expected-Schema-Hash", "empty")
	w := httptest.NewRecorder()
	handler.upsertIdentityWorkforceProfile(w, request)
	if response.status != http.StatusOK || response.err != nil || repository.lastWorkforceProfile.ID != "workforce-1" {
		t.Fatalf("status=%d err=%v profile=%+v", response.status, response.err, repository.lastWorkforceProfile)
	}

	response.status, response.value, response.err = 0, nil, nil
	replay := workforceRequest(http.MethodPost, "/identity/workforce", []byte(`{"id":"workforce-1","organization_id":"organization-1","identity_user_id":"user-1","worker_no":"E-001","worker_type":"employee","work_status":"active"}`))
	replay.Header = request.Header.Clone()
	replayed := httptest.NewRecorder()
	handler.upsertIdentityWorkforceProfile(replayed, replay)
	if response.status != http.StatusOK || response.err != nil || replayed.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("replay status=%d header=%q err=%v", response.status, replayed.Header().Get("Idempotency-Replayed"), response.err)
	}
}

func TestIdentityWorkforceHandlersRoundTripProfilesAndAssignments(t *testing.T) {
	profile := identitymodel.IdentityWorkforceProfile{
		ID: "workforce-1", OrganizationID: "organization-1", IdentityUserID: "user-1", WorkerNo: "E-001",
		WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
	}
	assignment := identitymodel.IdentityWorkforceAssignment{
		ID: "assignment-1", WorkforceProfileID: profile.ID, OrganizationUnitID: "sales",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
	}
	repository := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{
			{ID: "user-1", Status: identitymodel.IdentityStatusActive},
			{ID: "login-only", Status: identitymodel.IdentityStatusActive},
		},
		workforceProfiles:    []identitymodel.IdentityWorkforceProfile{profile},
		workforceAssignments: []identitymodel.IdentityWorkforceAssignment{assignment},
		profileBindings: []identitymodel.IdentityProfileBinding{
			{BindingKey: "member", ObjectKey: "member_profile", ProfileID: "member-1", IdentityUserID: "user-1", Status: identitymodel.IdentityProfileBindingActive},
			{BindingKey: "student", ObjectKey: "student_profile", ProfileID: "student-1", IdentityUserID: "user-1", Status: identitymodel.IdentityProfileBindingUnlinked},
		},
	}
	handler, response := newIdentityHTTPHandler(repository)

	handler.listIdentityWorkforceProfiles(httptest.NewRecorder(), workforceRequest(http.MethodGet, "/", nil))
	if response.status != http.StatusOK {
		t.Fatalf("list profiles status=%d err=%v", response.status, response.err)
	}
	page, ok := response.value.(map[string]any)
	items, itemsOK := page["items"].([]identitymodel.IdentityWorkforceProfile)
	if !ok || !itemsOK || len(items) != 1 || items[0].IdentityUserID != "user-1" {
		t.Fatalf("workforce directory leaked a login-only account: %#v", response.value)
	}
	request := workforceRequest(http.MethodGet, "/", nil)
	request.SetPathValue("profileID", profile.ID)
	handler.getIdentityWorkforceProfile(httptest.NewRecorder(), request)
	if response.status != http.StatusOK {
		t.Fatalf("get profile status=%d err=%v", response.status, response.err)
	}
	handler.getIdentityWorkforceDetail(httptest.NewRecorder(), request)
	detail, detailOK := response.value.(identitymodel.IdentityWorkforceDetail)
	if response.status != http.StatusOK || !detailOK || detail.Account.ID != "user-1" ||
		len(detail.Assignments) != 1 || len(detail.BusinessProfiles) != 1 || detail.BusinessProfiles[0].BindingKey != "member" {
		t.Fatalf("workforce detail=%#v status=%d err=%v", response.value, response.status, response.err)
	}
	handler.listIdentityWorkforceAssignments(httptest.NewRecorder(), request)
	if response.status != http.StatusOK {
		t.Fatalf("list assignments status=%d err=%v", response.status, response.err)
	}

	create := workforceRequest(http.MethodPost, "/", []byte(`{"id":"workforce-2","organization_id":"organization-1","identity_user_id":"user-1","worker_no":"E-002","worker_type":"employee","work_status":"active"}`))
	handler.upsertIdentityWorkforceProfile(httptest.NewRecorder(), create)
	if response.status != http.StatusOK || repository.lastWorkforceProfile.ID != "workforce-2" {
		t.Fatalf("create profile status=%d profile=%#v err=%v", response.status, repository.lastWorkforceProfile, response.err)
	}
	update := workforceRequest(http.MethodPatch, "/", []byte(`{"organization_id":"organization-1","identity_user_id":"user-1","worker_no":"E-003","worker_type":"employee","work_status":"active"}`))
	update.SetPathValue("profileID", "workforce-3")
	handler.upsertIdentityWorkforceProfile(httptest.NewRecorder(), update)
	if repository.lastWorkforceProfile.ID != "workforce-3" {
		t.Fatalf("path profile id was not authoritative: %#v", repository.lastWorkforceProfile)
	}

	assign := workforceRequest(http.MethodPost, "/", []byte(`{"id":"assignment-2","organization_unit_id":"support","assignment_type":"secondary","status":"active"}`))
	assign.SetPathValue("profileID", profile.ID)
	handler.upsertIdentityWorkforceAssignment(httptest.NewRecorder(), assign)
	if response.status != http.StatusOK || repository.lastWorkforceAssignment.WorkforceProfileID != profile.ID {
		t.Fatalf("assignment status=%d assignment=%#v err=%v", response.status, repository.lastWorkforceAssignment, response.err)
	}
	validateProfile := workforceRequest(http.MethodPost, "/", []byte(`{"organization_id":"organization-1","identity_user_id":"user-1","worker_no":"E-004","worker_type":"employee","work_status":"active"}`))
	validateProfile.SetPathValue("profileID", "workforce-4")
	handler.validateIdentityWorkforceProfile(httptest.NewRecorder(), validateProfile)
	if response.status != http.StatusOK {
		t.Fatalf("validate profile status=%d err=%v", response.status, response.err)
	}
	validateAssignment := workforceRequest(http.MethodPost, "/", []byte(`{"id":"assignment-3","organization_unit_id":"finance","assignment_type":"secondary","status":"active"}`))
	validateAssignment.SetPathValue("profileID", profile.ID)
	handler.validateIdentityWorkforceAssignment(httptest.NewRecorder(), validateAssignment)
	if response.status != http.StatusOK {
		t.Fatalf("validate assignment status=%d err=%v", response.status, response.err)
	}
}

func TestIdentityWorkforceApplicationProjectionComposesFoundationFacts(t *testing.T) {
	manager := identitymodel.IdentityWorkforceProfile{
		ID: "manager-profile", OrganizationID: "organization-1", IdentityUserID: "manager-user", WorkerNo: "E-001",
		WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
	}
	employee := identitymodel.IdentityWorkforceProfile{
		ID: "employee-profile", OrganizationID: "organization-1", IdentityUserID: "employee-user", WorkerNo: "E-002",
		WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, PrimaryAssignmentID: "employee-primary",
	}
	repository := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{
			{ID: manager.IdentityUserID, Name: "Manager Name", Status: identitymodel.IdentityStatusActive},
			{ID: employee.IdentityUserID, Name: "Employee Name", Status: identitymodel.IdentityStatusActive},
		},
		departments:       []identitymodel.IdentityDepartment{{ID: "engineering", Name: "Engineering", Path: "/company/engineering", Status: identitymodel.IdentityStatusActive}},
		roles:             []identitymodel.IdentityRole{{ID: "sales-manager", Key: "sales_manager", Label: "Sales Manager", Status: identitymodel.IdentityStatusActive}},
		assignments:       []identitymodel.IdentityUserRoleAssignment{{UserID: employee.IdentityUserID, RoleID: "sales-manager", WorkforceProfileID: employee.ID, Status: "active"}},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{employee, manager},
		workforceAssignments: []identitymodel.IdentityWorkforceAssignment{{
			ID: "employee-primary", WorkforceProfileID: employee.ID, OrganizationUnitID: "engineering", PositionID: "position-engineer",
			ManagerWorkforceProfileID: manager.ID, AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
		}},
	}
	handler, response := newIdentityHTTPHandler(repository)

	handler.listIdentityWorkforceProfiles(httptest.NewRecorder(), workforceRequest(http.MethodGet, "/?projection=application", nil))
	page, ok := response.value.(identitymodel.IdentityWorkforceProjectionPage)
	if response.status != http.StatusOK || !ok || page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("application projection=%#v status=%d err=%v", response.value, response.status, response.err)
	}
	item := page.Items[1]
	if item.Profile.ID != employee.ID || item.DisplayName != "Employee Name" || item.PrimaryAssignment == nil ||
		item.PrimaryAssignment.PositionID != "position-engineer" || item.Department == nil || item.Department.Name != "Engineering" ||
		item.Manager == nil || item.Manager.IdentityUserID != manager.IdentityUserID || item.Manager.DisplayName != "Manager Name" ||
		len(item.Roles) != 1 || item.Roles[0].Key != "sales_manager" || item.Roles[0].ID != "sales-manager" || item.Roles[0].Label != "Sales Manager" {
		t.Fatalf("employee projection=%#v", item)
	}
}

func TestIdentityWorkforceOnboardingHandlerUsesOneAtomicCommand(t *testing.T) {
	repository := &identityHTTPRepository{
		roles: []identitymodel.IdentityRole{{ID: "employee", Key: "employee", Label: "Employee"}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	body := []byte(`{
		"user":{"id":"user-new","name":"New User","email":"new@example.test","status":"active"},
		"profile":{"id":"workforce-new","organization_id":"org-1","worker_no":"E-100","worker_type":"employee","start_date":"2026-07-25"},
		"assignment":{"id":"assignment-new","organization_unit_id":"unit-1","effective_from":"2026-07-25"},
		"role_ids":["employee"],
		"reason":"new hire"
	}`)
	handler.onboardIdentityWorkforce(httptest.NewRecorder(), workforceRequest(http.MethodPost, "/", body))
	if response.status != http.StatusCreated || response.err != nil {
		t.Fatalf("status=%d value=%#v err=%v", response.status, response.value, response.err)
	}
	mutation := repository.lastWorkforceOnboarding
	if mutation.User.ID != "user-new" || mutation.Profile.IdentityUserID != "user-new" ||
		mutation.Profile.PrimaryAssignmentID != "assignment-new" || len(mutation.RoleAssignments) != 1 ||
		mutation.Reason != "new hire" {
		t.Fatalf("unexpected onboarding mutation: %#v", mutation)
	}
	handler.onboardIdentityWorkforce(httptest.NewRecorder(), workforceRequest(http.MethodPost, "/", []byte(`{`)))
	if response.status != http.StatusBadRequest {
		t.Fatalf("invalid JSON status=%d", response.status)
	}
	repository.err = errIdentityHTTPTest
	response.status, response.value, response.err = 0, nil, nil
	failureRequest := workforceRequest(http.MethodPost, "/", body)
	failureRequest.Header.Set("Idempotency-Key", "workforce-failure-command")
	handler.onboardIdentityWorkforce(httptest.NewRecorder(), failureRequest)
	if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
		t.Fatalf("failure status=%d err=%v", response.status, response.err)
	}
}

func TestIdentityWorkforceTransferBatchHandlerReturnsReceipt(t *testing.T) {
	repository := &identityHTTPRepository{
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{{
			ID: "workforce-1", OrganizationID: "org-1", IdentityUserID: "user-1", WorkerNo: "E-1",
			WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
		}},
		workforceAssignments: []identitymodel.IdentityWorkforceAssignment{{
			ID: "assignment-1", WorkforceProfileID: "workforce-1", OrganizationUnitID: "unit-1",
			AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
		}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	request := workforceRequest(http.MethodPost, "/", []byte(`{"items":[{
		"profile_id":"workforce-1","previous_assignment_id":"assignment-1","effective_at":"2026-07-25",
		"assignment":{"id":"assignment-new","organization_unit_id":"unit-2"}
	}]}`))
	request.Header.Set("Idempotency-Key", "transfer-batch-1")
	handler.applyIdentityWorkforceTransferBatch(httptest.NewRecorder(), request)
	receipt, ok := response.value.(identitymodel.IdentityWorkforceTransferBatchReceipt)
	if response.status != http.StatusOK || !ok || receipt.IdempotencyKey != "transfer-batch-1" || len(receipt.Items) != 1 {
		t.Fatalf("status=%d receipt=%#v err=%v", response.status, response.value, response.err)
	}
}

func TestIdentityWorkforceLifecycleHandlerUsesPathProfileAndPrincipal(t *testing.T) {
	repository := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	request := workforceRequest(http.MethodPost, "/", []byte(`{
		"operation":"invite",
		"profile":{"organization_id":"org-1","identity_user_id":"user-1","worker_no":"E-1","worker_type":"employee"},
		"reason":"controlled invite"
	}`))
	request.SetPathValue("profileID", "workforce-1")
	handler.applyIdentityWorkforceLifecycle(httptest.NewRecorder(), request)
	if response.status != http.StatusOK || repository.lastWorkforceLifecycle.Profile == nil {
		t.Fatalf("status=%d mutation=%#v err=%v", response.status, repository.lastWorkforceLifecycle, response.err)
	}
	if repository.lastWorkforceLifecycle.Profile.ID != "workforce-1" ||
		repository.lastWorkforceLifecycle.Profile.WorkStatus != identitymodel.IdentityWorkPending ||
		repository.lastWorkforceLifecycle.ActorID != "reviewer-1" ||
		repository.lastWorkforceLifecycle.Reason != "controlled invite" {
		t.Fatalf("lifecycle mutation=%#v", repository.lastWorkforceLifecycle)
	}

	mismatch := workforceRequest(http.MethodPost, "/", []byte(`{"operation":"invite","profile":{"id":"other"}}`))
	mismatch.SetPathValue("profileID", "workforce-1")
	handler.applyIdentityWorkforceLifecycle(httptest.NewRecorder(), mismatch)
	if response.status != http.StatusBadRequest {
		t.Fatalf("mismatch status=%d", response.status)
	}
}

func TestIdentityWorkforceLifecyclePersistsReplayAndRejectsKeyReuse(t *testing.T) {
	repository := &identityHTTPRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{
			Known: true, WorkspaceID: "workspace-1", UserID: "hr-1",
			Role: identitymodel.RoleSchema{Permissions: []string{"identity.workforce.lifecycle"}},
		}
	}
	body := []byte(`{
		"operation":"invite",
		"profile":{"organization_id":"org-1","identity_user_id":"user-1","worker_no":"E-1","worker_type":"employee"},
		"reason":"controlled invite"
	}`)
	invoke := func(body []byte) *httptest.ResponseRecorder {
		request := workforceRequest(http.MethodPost, "/", body)
		request.Header.Set("Idempotency-Key", "lifecycle-invite-1")
		request.SetPathValue("profileID", "workforce-1")
		writer := httptest.NewRecorder()
		handler.applyIdentityWorkforceLifecycle(writer, request)
		return writer
	}

	first := invoke(body)
	if response.status != http.StatusOK || response.err != nil || first.Header().Get("Operation-ID") == "" || first.Header().Get("Idempotency-Replayed") != "" {
		t.Fatalf("first status=%d headers=%v err=%v", response.status, first.Header(), response.err)
	}

	repository.err = errIdentityHTTPTest
	response.status, response.value, response.err = 0, nil, nil
	replay := invoke(body)
	if response.status != http.StatusOK || response.err != nil || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("replay status=%d headers=%v err=%v", response.status, replay.Header(), response.err)
	}

	response.status, response.value, response.err = 0, nil, nil
	changed := invoke([]byte(`{"operation":"invite","profile":{"organization_id":"org-1","identity_user_id":"user-1","worker_no":"E-2","worker_type":"employee"},"reason":"changed"}`))
	if apperror.CodeOf(response.err) != idempotency.ErrorCodeKeyReused || changed.Header().Get("Idempotency-Replayed") != "" {
		t.Fatalf("changed headers=%v err=%v", changed.Header(), response.err)
	}
}

func TestIdentityWorkforceHandlersRejectProtocolAndRepositoryFailures(t *testing.T) {
	repository := &identityHTTPRepository{
		users:             []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{{ID: "workforce-1", OrganizationID: "organization-1", IdentityUserID: "user-1", WorkerNo: "E-001", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	missing := workforceRequest(http.MethodGet, "/", nil)
	missing.SetPathValue("profileID", "missing")
	handler.getIdentityWorkforceProfile(httptest.NewRecorder(), missing)
	if response.status != http.StatusNotFound {
		t.Fatalf("missing status=%d", response.status)
	}
	mismatch := workforceRequest(http.MethodPatch, "/", []byte(`{"id":"other"}`))
	mismatch.SetPathValue("profileID", "expected")
	handler.upsertIdentityWorkforceProfile(httptest.NewRecorder(), mismatch)
	if response.status != http.StatusBadRequest {
		t.Fatalf("profile mismatch status=%d", response.status)
	}
	assignmentMismatch := workforceRequest(http.MethodPost, "/", []byte(`{"id":"assignment","workforce_profile_id":"other"}`))
	assignmentMismatch.SetPathValue("profileID", "expected")
	handler.upsertIdentityWorkforceAssignment(httptest.NewRecorder(), assignmentMismatch)
	if response.status != http.StatusBadRequest {
		t.Fatalf("assignment mismatch status=%d", response.status)
	}
	invalid := workforceRequest(http.MethodPost, "/", []byte(`{`))
	handler.upsertIdentityWorkforceProfile(httptest.NewRecorder(), invalid)
	if response.status != http.StatusBadRequest {
		t.Fatalf("invalid JSON status=%d", response.status)
	}
	handler.validateIdentityWorkforceAssignment(httptest.NewRecorder(), invalid)
	if response.status != http.StatusBadRequest {
		t.Fatalf("invalid assignment JSON status=%d", response.status)
	}

	repository.err = errIdentityHTTPTest
	handler.listIdentityWorkforceProfiles(httptest.NewRecorder(), workforceRequest(http.MethodGet, "/", nil))
	if response.err != errIdentityHTTPTest {
		t.Fatalf("list error=%v", response.err)
	}
	handler.getIdentityWorkforceProfile(httptest.NewRecorder(), missing)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("get error=%v", response.err)
	}
	handler.listIdentityWorkforceAssignments(httptest.NewRecorder(), missing)
	if response.err != errIdentityHTTPTest {
		t.Fatalf("assignment list error=%v", response.err)
	}
}

func TestIdentityWorkforceTerminationPreservesAccountBoundary(t *testing.T) {
	profile := identitymodel.IdentityWorkforceProfile{
		ID: "workforce-1", OrganizationID: "organization-1", IdentityUserID: "user-1", WorkerNo: "E-001",
		WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
	}
	repository := &identityHTTPRepository{
		users:             []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{profile},
		profileBindings:   []identitymodel.IdentityProfileBinding{{IdentityUserID: "user-1", ObjectKey: "member", ProfileID: "member-1", Status: identitymodel.IdentityProfileBindingActive}},
	}
	handler, response := newIdentityHTTPHandler(repository)
	request := workforceRequest(http.MethodPost, "/", []byte(`{"effective_at":"2026-07-25","reason":"employment ended"}`))
	request.SetPathValue("profileID", profile.ID)
	handler.terminateIdentityWorkforceProfile(httptest.NewRecorder(), request)
	if response.status != http.StatusOK || response.err != nil {
		t.Fatalf("status=%d err=%v", response.status, response.err)
	}
	mutation := repository.lastWorkforceTermination
	if mutation.ActorID != "reviewer-1" || mutation.Reason != "employment ended" {
		t.Fatalf("termination mutation=%+v", mutation)
	}
	if repository.users[0].Status != identitymodel.IdentityStatusActive || repository.profileBindings[0].Status != identitymodel.IdentityProfileBindingActive {
		t.Fatalf("termination crossed account/profile boundary: users=%+v bindings=%+v", repository.users, repository.profileBindings)
	}
}

func workforceRequest(method, target string, body []byte) *http.Request {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Idempotency-Key", "workforce-test-command")
	return request.WithContext(requestcontext.WithWorkspaceID(request.Context(), "workspace-1"))
}
