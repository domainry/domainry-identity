package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityEffectiveAccessStub struct {
	err           error
	userID        string
	explain       identitymodel.IdentityAccessExplainRequest
	roleChange    identitymodel.IdentityRoleChangeImpactRequest
	snapshot      identitymodel.IdentityEffectiveAccessSnapshot
	reverseIndex  identitymodel.IdentityAccessReverseIndex
	reports       identitymodel.IdentityGovernanceReports
	explainResult identitymodel.IdentityAccessExplainResult
	impact        identitymodel.IdentityRoleChangeImpact
}

func (stub *identityEffectiveAccessStub) Snapshot(_ context.Context, userID string, _ identitymodel.Principal) (identitymodel.IdentityEffectiveAccessSnapshot, error) {
	stub.userID = userID
	return stub.snapshot, stub.err
}

func (stub *identityEffectiveAccessStub) Explain(_ context.Context, request identitymodel.IdentityAccessExplainRequest, _ identitymodel.Principal) (identitymodel.IdentityAccessExplainResult, error) {
	stub.explain = request
	return stub.explainResult, stub.err
}

func (stub *identityEffectiveAccessStub) ReverseIndex(context.Context, identitymodel.Principal) (identitymodel.IdentityAccessReverseIndex, error) {
	return stub.reverseIndex, stub.err
}

func (stub *identityEffectiveAccessStub) GovernanceReports(context.Context, identitymodel.Principal) (identitymodel.IdentityGovernanceReports, error) {
	return stub.reports, stub.err
}

func (stub *identityEffectiveAccessStub) PreviewRoleChange(_ context.Context, request identitymodel.IdentityRoleChangeImpactRequest, _ identitymodel.Principal) (identitymodel.IdentityRoleChangeImpact, error) {
	stub.roleChange = request
	return stub.impact, stub.err
}

type identityAccessReviewsStub struct {
	err      error
	status   string
	itemID   string
	create   identitymodel.IdentityAccessReviewCreateRequest
	decision identitymodel.IdentityAccessReviewDecisionRequest
	review   identitymodel.IdentityAccessReview
	reviews  []identitymodel.IdentityAccessReview
	receipt  identitymodel.IdentityAccessReviewDecisionReceipt
}

func (stub *identityAccessReviewsStub) CreateReview(_ context.Context, request identitymodel.IdentityAccessReviewCreateRequest, _ identitymodel.Principal) (identitymodel.IdentityAccessReview, error) {
	stub.create = request
	return stub.review, stub.err
}

func (stub *identityAccessReviewsStub) ListReviews(_ context.Context, status string, _ identitymodel.Principal) ([]identitymodel.IdentityAccessReview, error) {
	stub.status = status
	return stub.reviews, stub.err
}

func (stub *identityAccessReviewsStub) Decide(_ context.Context, itemID string, request identitymodel.IdentityAccessReviewDecisionRequest, _ identitymodel.Principal) (identitymodel.IdentityAccessReviewDecisionReceipt, error) {
	stub.itemID, stub.decision = itemID, request
	return stub.receipt, stub.err
}

func newIdentityAccessTestHandler(access IdentityEffectiveAccess, reviews IdentityAccessReviews, decode bool) (*IdentityHandler, *error) {
	serviceErr := new(error)
	return NewIdentityHandler(IdentityDependencies{
		EffectiveAccess: access,
		AccessReviews:   reviews,
		Principal: func(*http.Request) identitymodel.Principal {
			return identitymodel.Principal{Known: true, WorkspaceID: "workspace", UserID: "admin"}
		},
		WriteJSON: func(w http.ResponseWriter, status int, value any) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(value)
		},
		WriteError: func(w http.ResponseWriter, _ *http.Request, status int, code string, _ ...string) {
			*serviceErr = errors.New(code)
			w.WriteHeader(status)
		},
		WriteServiceError: func(w http.ResponseWriter, _ *http.Request, err error) {
			*serviceErr = err
			w.WriteHeader(599)
		},
		DecodeJSON: func(w http.ResponseWriter, request *http.Request, target any) bool {
			if !decode {
				w.WriteHeader(http.StatusBadRequest)
				return false
			}
			if err := json.NewDecoder(request.Body).Decode(target); err != nil {
				*serviceErr = err
				w.WriteHeader(http.StatusBadRequest)
				return false
			}
			return true
		},
	}), serviceErr
}

func identityAccessRequest(method, target, body string, pathValues map[string]string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	for key, value := range pathValues {
		request.SetPathValue(key, value)
	}
	return request
}

func TestIdentityAccessHandlersUnavailableAndDecodeFailures(t *testing.T) {
	handler, serviceErr := newIdentityAccessTestHandler(nil, nil, true)
	calls := []struct {
		call func(http.ResponseWriter, *http.Request)
		req  *http.Request
	}{
		{handler.getIdentityEffectiveAccess, identityAccessRequest(http.MethodGet, "/", "", nil)},
		{handler.explainIdentityEffectiveAccess, identityAccessRequest(http.MethodPost, "/", `{}`, nil)},
		{handler.getIdentityAccessReverseIndex, identityAccessRequest(http.MethodGet, "/", "", nil)},
		{handler.getIdentityAccessGovernanceReports, identityAccessRequest(http.MethodGet, "/", "", nil)},
		{handler.previewIdentityRoleChangeImpact, identityAccessRequest(http.MethodPost, "/", `{}`, nil)},
		{handler.createIdentityAccessReview, identityAccessRequest(http.MethodPost, "/", `{}`, nil)},
		{handler.listIdentityAccessReviews, identityAccessRequest(http.MethodGet, "/", "", nil)},
		{handler.decideIdentityAccessReviewItem, identityAccessRequest(http.MethodPost, "/", `{}`, nil)},
	}
	for _, call := range calls {
		*serviceErr = nil
		response := httptest.NewRecorder()
		call.call(response, call.req)
		if response.Code != http.StatusServiceUnavailable || *serviceErr == nil {
			t.Fatalf("unavailable status=%d error=%v", response.Code, *serviceErr)
		}
	}

	access, reviews := &identityEffectiveAccessStub{}, &identityAccessReviewsStub{}
	handler, _ = newIdentityAccessTestHandler(access, reviews, false)
	for _, call := range []func(http.ResponseWriter, *http.Request){
		handler.explainIdentityEffectiveAccess,
		handler.previewIdentityRoleChangeImpact,
		handler.createIdentityAccessReview,
		handler.decideIdentityAccessReviewItem,
	} {
		response := httptest.NewRecorder()
		call(response, identityAccessRequest(http.MethodPost, "/", `{}`, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("decode failure status=%d", response.Code)
		}
	}
}

func TestIdentityAccessHandlersSuccessAndServiceFailures(t *testing.T) {
	access := &identityEffectiveAccessStub{}
	reviews := &identityAccessReviewsStub{reviews: []identitymodel.IdentityAccessReview{{ID: "review-1"}}}
	handler, serviceErr := newIdentityAccessTestHandler(access, reviews, true)
	calls := []struct {
		name       string
		call       func(http.ResponseWriter, *http.Request)
		req        func() *http.Request
		wantStatus int
	}{
		{name: "snapshot", call: handler.getIdentityEffectiveAccess, req: func() *http.Request {
			return identityAccessRequest(http.MethodGet, "/", "", map[string]string{"userID": " user-1 "})
		}, wantStatus: http.StatusOK},
		{name: "explain", call: handler.explainIdentityEffectiveAccess, req: func() *http.Request {
			return identityAccessRequest(http.MethodPost, "/", `{}`, nil)
		}, wantStatus: http.StatusOK},
		{name: "reverse index", call: handler.getIdentityAccessReverseIndex, req: func() *http.Request {
			return identityAccessRequest(http.MethodGet, "/", "", nil)
		}, wantStatus: http.StatusOK},
		{name: "governance reports", call: handler.getIdentityAccessGovernanceReports, req: func() *http.Request {
			return identityAccessRequest(http.MethodGet, "/", "", nil)
		}, wantStatus: http.StatusOK},
		{name: "role impact", call: handler.previewIdentityRoleChangeImpact, req: func() *http.Request {
			return identityAccessRequest(http.MethodPost, "/", `{}`, map[string]string{"roleID": " role-1 "})
		}, wantStatus: http.StatusOK},
		{name: "create review", call: handler.createIdentityAccessReview, req: func() *http.Request {
			return identityAccessRequest(http.MethodPost, "/", `{}`, nil)
		}, wantStatus: http.StatusCreated},
		{name: "list reviews", call: handler.listIdentityAccessReviews, req: func() *http.Request {
			return identityAccessRequest(http.MethodGet, "/?status=active", "", nil)
		}, wantStatus: http.StatusOK},
		{name: "decide review", call: handler.decideIdentityAccessReviewItem, req: func() *http.Request {
			return identityAccessRequest(http.MethodPost, "/", `{}`, map[string]string{"itemID": " item-1 "})
		}, wantStatus: http.StatusOK},
	}
	for _, call := range calls {
		t.Run(call.name+" success", func(t *testing.T) {
			*serviceErr = nil
			response := httptest.NewRecorder()
			call.call(response, call.req())
			if response.Code != call.wantStatus || *serviceErr != nil {
				t.Fatalf("status=%d error=%v body=%s", response.Code, *serviceErr, response.Body.String())
			}
		})
	}
	if access.userID != "user-1" || access.roleChange.RoleKey != "role-1" || reviews.status != "active" || reviews.itemID != "item-1" {
		t.Fatalf("projected inputs user=%q role=%q status=%q item=%q", access.userID, access.roleChange.RoleKey, reviews.status, reviews.itemID)
	}

	want := errors.New("service unavailable")
	access.err, reviews.err = want, want
	for _, call := range calls {
		t.Run(call.name+" error", func(t *testing.T) {
			*serviceErr = nil
			response := httptest.NewRecorder()
			call.call(response, call.req())
			if response.Code != 599 || !errors.Is(*serviceErr, want) {
				t.Fatalf("status=%d error=%v", response.Code, *serviceErr)
			}
		})
	}
}
