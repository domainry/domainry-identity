package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
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

func TestIdentityActionGateUsesRegisteredPermissionForAllowAndDeny(t *testing.T) {
	registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	action, ok := registry.Definition(identityapplication.IdentityActionPermissionsList)
	if !ok {
		t.Fatal("permission list action is not registered")
	}
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Key: "viewer"}}
	handler := &IdentityHandler{
		principal:     func(*http.Request) identitymodel.Principal { return principal },
		writeError:    func(w http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) { w.WriteHeader(status) },
		securityAudit: func(*http.Request, string, string, map[string]any) {},
	}
	executed := false
	protected := handler.identityAction(action, func(w http.ResponseWriter, _ *http.Request) {
		executed = true
		w.WriteHeader(http.StatusNoContent)
	})
	denied := httptest.NewRecorder()
	protected(denied, httptest.NewRequest(http.MethodGet, "/identity/permissions", nil))
	if denied.Code != http.StatusForbidden || executed {
		t.Fatalf("denied status=%d executed=%v", denied.Code, executed)
	}
	principal.Role.Permissions = []string{"identity.permissions.read"}
	allowed := httptest.NewRecorder()
	protected(allowed, httptest.NewRequest(http.MethodGet, "/identity/permissions", nil))
	if allowed.Code != http.StatusNoContent || !executed {
		t.Fatalf("allowed status=%d executed=%v", allowed.Code, executed)
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
