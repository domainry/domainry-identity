package httpserver

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-identity-sdk/browsergateway"
	authhttp "github.com/domainry/domainry-identity/internal/transport/http/auth"
)

func TestEmbeddedAuthRouteInventoryOwnsEveryNonBrowserRoute(t *testing.T) {
	authRoutes := &recordingRouteRegistrar{mux: http.NewServeMux()}
	authhttp.NewAuthHandler(authhttp.AuthDependencies{Authenticated: func(next http.HandlerFunc) http.HandlerFunc { return next }}).RegisterRoutes(authRoutes)
	browserRoutes, err := browsergateway.RoutePatterns("")
	if err != nil {
		t.Fatal(err)
	}
	publicRoutes, managementRoutes := embeddedAuthRouteInventory(authRoutes.patterns, browserRoutes)
	wantPublic := []string{
		"GET /.well-known/jwks.json",
		"GET /.well-known/openid-configuration",
		"POST /auth/guest",
		"POST /auth/providers/{provider}/exchange",
		"GET /auth/external-accounts",
		"POST /auth/external-accounts/{provider}/bind",
		"DELETE /auth/external-accounts/{provider}/{accountID}",
		"GET /auth/me",
		"PATCH /auth/me",
		"GET /auth/role-options",
		"GET /auth/role-requests",
		"POST /auth/role-requests",
	}
	wantManagement := []string{
		"POST /auth/reset-password",
		"GET /auth/providers/{provider}/setup-check",
		"PUT /auth/providers/{provider}/setup",
	}
	if !reflect.DeepEqual(publicRoutes, wantPublic) {
		t.Fatalf("embedded public auth routes=%#v want=%#v", publicRoutes, wantPublic)
	}
	if !reflect.DeepEqual(managementRoutes, wantManagement) {
		t.Fatalf("embedded management auth routes=%#v want=%#v", managementRoutes, wantManagement)
	}
	owned := map[string]bool{}
	for _, routes := range [][]string{browserRoutes, publicRoutes, managementRoutes} {
		for _, pattern := range routes {
			owned[pattern] = true
		}
	}
	for _, pattern := range authRoutes.patterns {
		if !owned[pattern] {
			t.Fatalf("AuthHandler route %q has no embedded owner", pattern)
		}
	}
}

func TestClassifyRouteSurface(t *testing.T) {
	tests := map[string]routeSurface{
		"GET /browser/auth/login":                     routeSurfacePublic,
		"GET /identity/discovery":                     routeSurfacePublic,
		"GET /identity/users":                         routeSurfaceTenantAdmin,
		"GET /tenant-admin/runtime-schema":            routeSurfaceTenantAdmin,
		"PUT /auth/providers/oidc/setup":              routeSurfaceTenantAdmin,
		"POST /ops/identity-portability/write-fences": routeSurfaceOperations,
	}
	for requestTarget, want := range tests {
		method, path, _ := strings.Cut(requestTarget, " ")
		if got := classifyRouteSurface(method, path); got != want {
			t.Fatalf("classify %q=%q want=%q", requestTarget, got, want)
		}
	}
}

func TestHTTPControlsApplyIndependentRateLimitsAndTimeout(t *testing.T) {
	support := newHTTPSupport(nil, nil, httpControlConfig{
		PublicMaxJSONBodyBytes: 128, TenantAdminMaxJSONBodyBytes: 128, OperationsMaxJSONBodyBytes: 16,
		PublicRequestTimeout: time.Minute, TenantAdminRequestTimeout: time.Minute, OperationsRequestTimeout: time.Second,
		PublicRateLimitPerMinute: 1, TenantAdminRateLimitPerMinute: 1, OperationsRateLimitPerMinute: 1,
	})
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	support.controls.clock = func() time.Time { return now }
	handler := support.middleware(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if classifyRouteSurface(request.Method, request.URL.Path) == routeSurfaceOperations {
			deadline, ok := request.Context().Deadline()
			if !ok || time.Until(deadline) > 2*time.Second {
				t.Errorf("operations request deadline=%v ok=%v", deadline, ok)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	assertStatus := func(path string, want int) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != want {
			t.Fatalf("GET %s status=%d want=%d body=%s", path, response.Code, want, response.Body.String())
		}
	}
	assertStatus("/healthz", http.StatusNoContent)
	assertStatus("/healthz", http.StatusTooManyRequests)
	assertStatus("/identity/users", http.StatusNoContent)
	assertStatus("/ops/identity-portability/write-fences", http.StatusNoContent)
}

func TestHTTPControlsApplySurfaceBodyLimitsAndListenerIsolation(t *testing.T) {
	support := newHTTPSupport(nil, nil, httpControlConfig{PublicMaxJSONBodyBytes: 128, OperationsMaxJSONBodyBytes: 8})
	decode := func(path string) int {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"value":"payload"}`))
		var value map[string]any
		if support.decodeJSON(response, request, &value) {
			return http.StatusNoContent
		}
		return response.Code
	}
	if status := decode("/browser/auth/login"); status != http.StatusNoContent {
		t.Fatalf("public body status=%d", status)
	}
	if status := decode("/ops/identity-portability/write-fences"); status != http.StatusBadRequest {
		t.Fatalf("operations oversized body status=%d", status)
	}

	public := surfaceOnly(routeSurfacePublic, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for path, want := range map[string]int{"/browser/auth/login": http.StatusNoContent, "/identity/users": http.StatusNotFound, "/ops/identity-portability/write-fences": http.StatusNotFound} {
		response := httptest.NewRecorder()
		public.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != want {
			t.Fatalf("public listener %s status=%d want=%d", path, response.Code, want)
		}
	}
}
