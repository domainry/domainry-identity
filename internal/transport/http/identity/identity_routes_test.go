package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityRoutesBindMethodsAndPaths(t *testing.T) {
	handler, _ := newIdentityHTTPHandler(&identityHTTPRepository{})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodPatch, "/identity/roles", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method route status=%d", response.Code)
	}
}

func TestWorkforceApplicationProjectionRequiresWorkforceReadPermission(t *testing.T) {
	handler := NewIdentityHandler(IdentityDependencies{
		Principal: func(*http.Request) identitymodel.Principal {
			return identitymodel.Principal{Known: true, WorkspaceID: "workspace-1"}
		},
		WriteError: func(w http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) {
			w.WriteHeader(status)
		},
		SecurityAudit: func(*http.Request, string, string, map[string]any) {},
	})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/identity/workforce?projection=application", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("workforce projection without identity.workforce.read status=%d", response.Code)
	}
}
