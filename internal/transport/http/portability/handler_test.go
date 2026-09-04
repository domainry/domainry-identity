package portabilityhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	portabilityapplication "github.com/domainry/domainry-identity/internal/application/portability"
	portabilitymodel "github.com/domainry/domainry-identity/internal/domain/portability"
)

type portabilityRepositoryStub struct{}

func (portabilityRepositoryStub) Inventory(_ context.Context, workspaceID string) (portabilitymodel.Inventory, error) {
	return portabilitymodel.Inventory{WorkspaceID: workspaceID, DatasetCounts: map[string]int64{"users": 1}, ExcludedCounts: map[string]int64{}, ProviderKeys: []string{}}, nil
}

func (portabilityRepositoryStub) MetadataSchemaSHA256(context.Context) (string, error) {
	return strings.Repeat("a", 64), nil
}

func (portabilityRepositoryStub) Export(context.Context, string) ([]portabilitymodel.Dataset, []portabilitymodel.ProviderReference, map[string]int64, error) {
	return nil, nil, nil, nil
}

func (portabilityRepositoryStub) RecordExport(context.Context, portabilitymodel.Bundle) error {
	return nil
}

func (portabilityRepositoryStub) FreezeWrites(_ context.Context, workspaceID, _ string, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
	return portabilitymodel.WriteFence{WorkspaceID: workspaceID, State: "frozen", FrozenBy: operator, FrozenAt: now}, nil
}

func (portabilityRepositoryStub) ReleaseWriteFence(_ context.Context, workspaceID, operator string, now time.Time) (portabilitymodel.WriteFence, error) {
	return portabilitymodel.WriteFence{WorkspaceID: workspaceID, State: "released", ReleasedBy: operator, ReleasedAt: &now}, nil
}

func (portabilityRepositoryStub) VerifyWriteFreeze(context.Context, string) error { return nil }

func (portabilityRepositoryStub) VerifyProviderReadiness(context.Context, string, []portabilitymodel.ProviderReference) error {
	return nil
}

func (portabilityRepositoryStub) Import(context.Context, portabilitymodel.Bundle, string, time.Time) (portabilitymodel.ImportReceipt, error) {
	return portabilitymodel.ImportReceipt{}, nil
}

func TestPortabilityOperationsRequireDedicatedBearerToken(t *testing.T) {
	service, err := portabilityapplication.NewService(portabilityRepositoryStub{}, portabilityapplication.Options{SchemaVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	NewHandler(Dependencies{
		Service: service, AccessToken: "operations-token",
		DecodeJSON: func(w http.ResponseWriter, request *http.Request, value any) bool {
			if err := json.NewDecoder(request.Body).Decode(value); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return false
			}
			return true
		},
		WriteJSON: func(w http.ResponseWriter, status int, value any) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(value)
		},
		WriteError: func(w http.ResponseWriter, _ *http.Request, status int, code string, _ ...string) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(code))
		},
	}).RegisterRoutes(mux)

	request := func(token string) *http.Request {
		value := httptest.NewRequest(http.MethodPost, "/identity/portability/write-fences", strings.NewReader(`{"workspace_id":"workspace-a","evidence":"ticket-1","operator":"operator-1"}`))
		if token != "" {
			value.Header.Set("Authorization", "Bearer "+token)
		}
		return value
	}
	unauthorized := httptest.NewRecorder()
	mux.ServeHTTP(unauthorized, request("wrong"))
	if unauthorized.Code != http.StatusUnauthorized || !strings.Contains(unauthorized.Body.String(), "identity.operations_token_invalid") {
		t.Fatalf("unauthorized status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	authorized := httptest.NewRecorder()
	mux.ServeHTTP(authorized, request("operations-token"))
	if authorized.Code != http.StatusOK || !strings.Contains(authorized.Body.String(), `"workspace_id":"workspace-a"`) || !strings.Contains(authorized.Body.String(), `"state":"frozen"`) {
		t.Fatalf("authorized status=%d body=%s", authorized.Code, authorized.Body.String())
	}
}

func TestPortabilityHTTPDoesNotOwnImportOrExportRoutes(t *testing.T) {
	mux := http.NewServeMux()
	NewHandler(Dependencies{}).RegisterRoutes(mux)
	for _, path := range []string{"/identity/portability/exports", "/identity/portability/imports"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("retired route %s status=%d want=%d", path, response.Code, http.StatusNotFound)
		}
	}
}
