package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityPrincipalContextRouteRequiresAuthenticationAndReturnsCurrentPrincipal(t *testing.T) {
	known := true
	handler := NewIdentityHandler(IdentityDependencies{
		Principal: func(*http.Request) identitymodel.Principal {
			return identitymodel.Principal{Known: known, WorkspaceID: "workspace-1", UserID: "user-1", OrgID: "sales"}
		},
		WriteJSON: func(w http.ResponseWriter, status int, value any) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(value)
		},
		WriteError:    func(w http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) { w.WriteHeader(status) },
		SecurityAudit: func(*http.Request, string, string, map[string]any) {},
	})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/identity/principal-context", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("principal context status=%d body=%s", response.Code, response.Body.String())
	}
	var context identitymodel.IdentityPrincipalContext
	if err := json.NewDecoder(response.Body).Decode(&context); err != nil {
		t.Fatal(err)
	}
	if context.ContractVersion != identitymodel.IdentityPrincipalContextContractV1 || context.UserID != "user-1" || context.OrgID != "sales" || len(context.RequestContexts) != 1 {
		t.Fatalf("principal context=%+v", context)
	}

	known = false
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/identity/principal-context", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unknown principal status=%d", response.Code)
	}
}
