package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityWorkforceRemainingDecodeFailures(t *testing.T) {
	tests := []struct {
		name   string
		invoke func(*IdentityHandler, *http.Request)
	}{
		{
			name: "lifecycle",
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.applyIdentityWorkforceLifecycle(httptest.NewRecorder(), request)
			},
		},
		{
			name: "transfer batch",
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.applyIdentityWorkforceTransferBatch(httptest.NewRecorder(), request)
			},
		},
		{
			name: "rehire",
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.rehireIdentityWorkforce(httptest.NewRecorder(), request)
			},
		},
		{
			name: "validate profile",
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.validateIdentityWorkforceProfile(httptest.NewRecorder(), request)
			},
		},
		{
			name: "terminate",
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.terminateIdentityWorkforceProfile(httptest.NewRecorder(), request)
			},
		},
		{
			name: "upsert assignment",
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.upsertIdentityWorkforceAssignment(httptest.NewRecorder(), request)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
			request := workforceRequest(http.MethodPost, "/", []byte(`{`))
			request.SetPathValue("profileID", "workforce-1")
			test.invoke(handler, request)
			if response.status != http.StatusBadRequest || response.err == nil {
				t.Fatalf("status=%d err=%v", response.status, response.err)
			}
		})
	}
}

func TestIdentityWorkforceRemainingServiceFailures(t *testing.T) {
	activeProfile := identitymodel.IdentityWorkforceProfile{
		ID: "workforce-1", OrganizationID: "org-1", IdentityUserID: "user-1", WorkerNo: "E-1",
		WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
	}
	tests := []struct {
		name   string
		body   string
		invoke func(*IdentityHandler, *http.Request)
	}{
		{
			name: "lifecycle",
			body: `{"operation":"invite","profile":{"id":"workforce-1","organization_id":"org-1","identity_user_id":"user-1","worker_no":"E-1","worker_type":"employee"}}`,
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.applyIdentityWorkforceLifecycle(httptest.NewRecorder(), request)
			},
		},
		{
			name: "transfer batch",
			body: `{"items":[{"profile_id":"workforce-1","previous_assignment_id":"assignment-1","effective_at":"2026-08-01","assignment":{"id":"assignment-2","organization_unit_id":"unit-2"}}]}`,
			invoke: func(handler *IdentityHandler, request *http.Request) {
				request.Header.Set("Idempotency-Key", "transfer-failure")
				handler.applyIdentityWorkforceTransferBatch(httptest.NewRecorder(), request)
			},
		},
		{
			name: "rehire",
			body: `{"effective_at":"2026-08-01","assignment":{"id":"assignment-2","organization_unit_id":"unit-2"},"reason":"return"}`,
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.rehireIdentityWorkforce(httptest.NewRecorder(), request)
			},
		},
		{
			name: "upsert profile",
			body: `{"id":"workforce-1","organization_id":"org-1","identity_user_id":"user-1","worker_no":"E-1","worker_type":"employee","work_status":"active"}`,
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.upsertIdentityWorkforceProfile(httptest.NewRecorder(), request)
			},
		},
		{
			name: "validate profile",
			body: `{"id":"workforce-1","organization_id":"org-1","identity_user_id":"user-1","worker_no":"E-1","worker_type":"employee","work_status":"active"}`,
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.validateIdentityWorkforceProfile(httptest.NewRecorder(), request)
			},
		},
		{
			name: "terminate",
			body: `{"effective_at":"2026-08-01","reason":"ended"}`,
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.terminateIdentityWorkforceProfile(httptest.NewRecorder(), request)
			},
		},
		{
			name: "upsert assignment",
			body: `{"id":"assignment-2","workforce_profile_id":"workforce-1","organization_unit_id":"unit-2","assignment_type":"secondary","status":"active"}`,
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.upsertIdentityWorkforceAssignment(httptest.NewRecorder(), request)
			},
		},
		{
			name: "validate assignment",
			body: `{"id":"assignment-2","workforce_profile_id":"workforce-1","organization_unit_id":"unit-2","assignment_type":"secondary","status":"active"}`,
			invoke: func(handler *IdentityHandler, request *http.Request) {
				handler.validateIdentityWorkforceAssignment(httptest.NewRecorder(), request)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &identityHTTPRepository{
				err:               errIdentityHTTPTest,
				users:             []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
				workforceProfiles: []identitymodel.IdentityWorkforceProfile{activeProfile},
			}
			handler, response := newIdentityHTTPHandler(repository)
			request := workforceRequest(http.MethodPost, "/", []byte(test.body))
			request.SetPathValue("profileID", activeProfile.ID)
			test.invoke(handler, request)
			if response.status != http.StatusInternalServerError || response.err == nil {
				t.Fatalf("status=%d err=%v", response.status, response.err)
			}
		})
	}
}

func TestIdentityWorkforceDetailRemainingFailures(t *testing.T) {
	t.Run("repository error", func(t *testing.T) {
		handler, response := newIdentityHTTPHandler(&identityHTTPRepository{err: errIdentityHTTPTest})
		request := workforceRequest(http.MethodGet, "/", nil)
		request.SetPathValue("profileID", "workforce-1")
		handler.getIdentityWorkforceDetail(httptest.NewRecorder(), request)
		if response.status != http.StatusInternalServerError || response.err != errIdentityHTTPTest {
			t.Fatalf("status=%d err=%v", response.status, response.err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
		request := workforceRequest(http.MethodGet, "/", nil)
		request.SetPathValue("profileID", "missing")
		handler.getIdentityWorkforceDetail(httptest.NewRecorder(), request)
		if response.status != http.StatusNotFound {
			t.Fatalf("status=%d err=%v", response.status, response.err)
		}
	})
}

func TestIdentityWorkforceRemainingSuccessfulConditions(t *testing.T) {
	t.Run("matching lifecycle profile ID", func(t *testing.T) {
		repository := &identityHTTPRepository{
			users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		}
		handler, response := newIdentityHTTPHandler(repository)
		request := workforceRequest(http.MethodPost, "/", []byte(`{
			"operation":"invite",
			"profile":{"id":"workforce-1","organization_id":"org-1","identity_user_id":"user-1","worker_no":"E-1","worker_type":"employee"}
		}`))
		request.SetPathValue("profileID", "workforce-1")
		handler.applyIdentityWorkforceLifecycle(httptest.NewRecorder(), request)
		if response.status != http.StatusOK {
			t.Fatalf("status=%d err=%v", response.status, response.err)
		}
	})

	t.Run("matching profile ID", func(t *testing.T) {
		repository := &identityHTTPRepository{
			users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		}
		handler, response := newIdentityHTTPHandler(repository)
		request := workforceRequest(http.MethodPatch, "/", []byte(`{
			"id":"workforce-1","organization_id":"org-1","identity_user_id":"user-1",
			"worker_no":"E-1","worker_type":"employee","work_status":"active"
		}`))
		request.SetPathValue("profileID", "workforce-1")
		handler.upsertIdentityWorkforceProfile(httptest.NewRecorder(), request)
		if response.status != http.StatusOK {
			t.Fatalf("status=%d err=%v", response.status, response.err)
		}
	})

	t.Run("matching assignment profile ID", func(t *testing.T) {
		profile := identitymodel.IdentityWorkforceProfile{
			ID: "workforce-1", OrganizationID: "org-1", IdentityUserID: "user-1", WorkerNo: "E-1",
			WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
		}
		repository := &identityHTTPRepository{workforceProfiles: []identitymodel.IdentityWorkforceProfile{profile}}
		handler, response := newIdentityHTTPHandler(repository)
		request := workforceRequest(http.MethodPost, "/", []byte(`{
			"id":"assignment-2","workforce_profile_id":"workforce-1","organization_unit_id":"unit-2",
			"assignment_type":"secondary","status":"active"
		}`))
		request.SetPathValue("profileID", profile.ID)
		handler.upsertIdentityWorkforceAssignment(httptest.NewRecorder(), request)
		if response.status != http.StatusOK {
			t.Fatalf("status=%d err=%v", response.status, response.err)
		}
	})

	t.Run("rehire", func(t *testing.T) {
		profile := identitymodel.IdentityWorkforceProfile{
			ID: "workforce-1", OrganizationID: "org-1", IdentityUserID: "user-1", WorkerNo: "E-1",
			WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkTerminated,
			EndDate: "2026-07-01",
		}
		repository := &identityHTTPRepository{workforceProfiles: []identitymodel.IdentityWorkforceProfile{profile}}
		handler, response := newIdentityHTTPHandler(repository)
		request := workforceRequest(http.MethodPost, "/", []byte(`{
			"effective_at":"2026-08-01",
			"assignment":{"id":"assignment-2","organization_unit_id":"unit-2"},
			"reason":"return"
		}`))
		request.SetPathValue("profileID", profile.ID)
		handler.rehireIdentityWorkforce(httptest.NewRecorder(), request)
		if response.status != http.StatusOK {
			t.Fatalf("status=%d err=%v", response.status, response.err)
		}
	})
}
