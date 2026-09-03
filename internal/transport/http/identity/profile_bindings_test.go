package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type profileBindingHTTPRepository struct {
	binding identitymodel.IdentityProfileBinding
	found   bool
	err     error
}

func (r *profileBindingHTTPRepository) GetIdentityProfileBinding(context.Context, string, string, string) (identitymodel.IdentityProfileBinding, bool, error) {
	return r.binding, r.found, r.err
}
func (r *profileBindingHTTPRepository) GetIdentityProfileBindingByKey(context.Context, string, string, string) (identitymodel.IdentityProfileBinding, bool, error) {
	return r.binding, r.found, r.err
}
func (r *profileBindingHTTPRepository) GetIdentityProfileBindingReceipt(context.Context, identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, bool, error) {
	return identitymodel.IdentityProfileBindingReceipt{}, false, r.err
}
func (r *profileBindingHTTPRepository) ExecuteIdentityProfileBindingMutation(_ context.Context, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, error) {
	if r.err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, r.err
	}
	r.binding = identitymodel.IdentityProfileBinding{
		WorkspaceID: mutation.WorkspaceID, BindingKey: mutation.BindingKey, ObjectKey: mutation.ObjectKey,
		ProfileID: mutation.ProfileID, IdentityUserID: mutation.IdentityUserID, Status: identitymodel.IdentityProfileBindingActive, Version: mutation.ExpectedVersion + 1,
	}
	r.found = true
	return identitymodel.IdentityProfileBindingReceipt{ID: "receipt", BindingKey: mutation.BindingKey, ObjectKey: mutation.ObjectKey, ProfileID: mutation.ProfileID, Operation: mutation.Operation, Binding: r.binding}, nil
}
func (*profileBindingHTTPRepository) ListIdentityProfileBindingEvents(context.Context, string, string, string) ([]identitymodel.IdentityProfileBindingEvent, error) {
	return nil, nil
}

type profileBindingHTTPRecords struct{}

func (profileBindingHTTPRecords) GetIdentityProfileBindingRecord(context.Context, string, definitionmodel.ObjectSchema, string) (map[string]any, bool, error) {
	return map[string]any{"identity_user": nil}, true, nil
}

type profileBindingHTTPIdentity struct{}

func (profileBindingHTTPIdentity) FindUser(_ context.Context, userID string) (identitymodel.IdentityUser, bool, error) {
	return identitymodel.IdentityUser{ID: userID, Status: identitymodel.IdentityStatusActive}, true, nil
}

type profileBindingHTTPResponse struct {
	status int
	value  any
	err    error
}

func TestIdentityProfileBindingHTTPHandlers(t *testing.T) {
	repository := &profileBindingHTTPRepository{
		binding: identitymodel.IdentityProfileBinding{WorkspaceID: "workspace", BindingKey: "member", ObjectKey: "member_profile", ProfileID: "profile-1", IdentityUserID: "admin", Version: 1},
		found:   true,
	}
	response := &profileBindingHTTPResponse{}
	principal := identitymodel.Principal{Known: true, UserID: "admin", WorkspaceID: "workspace", Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(
		identitymodel.IdentityDataScopeAll, "identity.profile_bindings.get", "identity.profile_bindings.command",
	)}}
	service := identityapplication.NewIdentityProfileBindingApplicationService(identityapplication.IdentityProfileBindingDependencies{
		Repository: repository, Records: profileBindingHTTPRecords{}, Identity: profileBindingHTTPIdentity{},
		Objects: func() []definitionmodel.ObjectSchema {
			return []definitionmodel.ObjectSchema{{Key: "member_profile"}}
		},
		Extensions: func() []identitymodel.IdentityProfileExtension {
			return []identitymodel.IdentityProfileExtension{{
				ObjectKey: "member_profile", IdentityRelationField: "identity_user",
				BusinessIdentity: identitymodel.BusinessIdentityBinding{Key: "member"},
				BindingLifecycle: identitymodel.IdentityProfileBindingLifecycle{AllowUnbound: true},
			}}
		},
	})
	handler := NewIdentityHandler(IdentityDependencies{
		ProfileBindings: service,
		Principal:       func(*http.Request) identitymodel.Principal { return principal },
		WriteJSON:       func(_ http.ResponseWriter, status int, value any) { response.status, response.value = status, value },
		WriteError: func(_ http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) {
			response.status = status
		},
		WriteServiceError: func(_ http.ResponseWriter, _ *http.Request, err error) {
			response.err = err
		},
		DecodeJSON: func(_ http.ResponseWriter, request *http.Request, value any) bool {
			if err := json.NewDecoder(request.Body).Decode(value); err != nil {
				response.err = err
				return false
			}
			return true
		},
	})

	get := profileBindingHTTPRequest(http.MethodGet, "/identity/profile-bindings/member_profile/profile-1", nil)
	handler.getIdentityProfileBinding(httptest.NewRecorder(), get)
	if response.status != http.StatusOK {
		t.Fatalf("get response=%#v", response)
	}

	response = &profileBindingHTTPResponse{}
	command := profileBindingHTTPRequest(http.MethodPost, "/identity/profile-bindings/member_profile/profile-1/commands", strings.NewReader(`{"binding_key":"member","operation":"bind","identity_user_id":"target","expected_version":0,"idempotency_key":"bind-1","object_key":"attacker","profile_id":"attacker"}`))
	handler.writeJSON = func(_ http.ResponseWriter, status int, value any) { response.status, response.value = status, value }
	handler.writeServiceError = func(_ http.ResponseWriter, _ *http.Request, err error) { response.err = err }
	handler.executeIdentityProfileBindingCommand(httptest.NewRecorder(), command)
	receipt, ok := response.value.(identitymodel.IdentityProfileBindingReceipt)
	if response.status != http.StatusOK || !ok || receipt.ObjectKey != "member_profile" || receipt.ProfileID != "profile-1" {
		t.Fatalf("command response=%#v receipt=%#v", response, receipt)
	}

	repository.found = false
	response = &profileBindingHTTPResponse{}
	handler.writeError = func(_ http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) {
		response.status = status
	}
	handler.getIdentityProfileBinding(httptest.NewRecorder(), get)
	if response.status != http.StatusNotFound {
		t.Fatalf("missing response=%#v", response)
	}

	repository.found, repository.err = true, errors.New("binding failed")
	response = &profileBindingHTTPResponse{}
	handler.writeServiceError = func(_ http.ResponseWriter, _ *http.Request, err error) { response.err = err }
	handler.securityPrincipal = func(*http.Request, identitymodel.Principal, string, string, map[string]any) {}
	handler.getIdentityProfileBinding(httptest.NewRecorder(), get)
	if !errors.Is(response.err, repository.err) {
		t.Fatalf("error response=%#v", response)
	}

	response = &profileBindingHTTPResponse{}
	handler.writeServiceError = func(_ http.ResponseWriter, _ *http.Request, err error) { response.err = err }
	failedCommand := profileBindingHTTPRequest(http.MethodPost, "/identity/profile-bindings/member_profile/profile-1/commands", strings.NewReader(`{"binding_key":"member","operation":"bind","identity_user_id":"target","expected_version":1,"idempotency_key":"bind-failure"}`))
	handler.executeIdentityProfileBindingCommand(httptest.NewRecorder(), failedCommand)
	if !errors.Is(response.err, repository.err) {
		t.Fatalf("command error response=%#v", response)
	}
}

func TestIdentityProfileBindingHTTPUnavailableAndDecodeFailure(t *testing.T) {
	response := &profileBindingHTTPResponse{}
	handler := NewIdentityHandler(IdentityDependencies{
		Principal: func(*http.Request) identitymodel.Principal {
			return identitymodel.Principal{Known: true, WorkspaceID: "workspace"}
		},
		WriteError: func(_ http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) {
			response.status = status
		},
		DecodeJSON: func(http.ResponseWriter, *http.Request, any) bool {
			return false
		},
	})
	request := profileBindingHTTPRequest(http.MethodGet, "/", nil)
	handler.getIdentityProfileBinding(httptest.NewRecorder(), request)
	if response.status != http.StatusServiceUnavailable {
		t.Fatalf("get status=%d", response.status)
	}
	handler.executeIdentityProfileBindingCommand(httptest.NewRecorder(), request)
	if response.status != http.StatusServiceUnavailable {
		t.Fatalf("command status=%d", response.status)
	}

	handler.profileBindings = identityapplication.NewIdentityProfileBindingApplicationService(identityapplication.IdentityProfileBindingDependencies{})
	handler.executeIdentityProfileBindingCommand(httptest.NewRecorder(), request)
}

func profileBindingHTTPRequest(method, target string, body *strings.Reader) *http.Request {
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, body)
	}
	request.SetPathValue("objectKey", "member_profile")
	request.SetPathValue("profileID", "profile-1")
	return request
}
