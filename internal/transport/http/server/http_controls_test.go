package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClassifyRouteSurface(t *testing.T) {
	tests := map[string]routeSurface{
		"GET /browser/auth/login":                routeSurfacePublic,
		"GET /identity/discovery":                routeSurfacePublic,
		"GET /identity/users":                    routeSurfaceTenantAdmin,
		"GET /tenant-admin/runtime-schema":       routeSurfaceTenantAdmin,
		"PUT /auth/providers/oidc/setup":         routeSurfaceTenantAdmin,
		"POST /ops/identity-portability/exports": routeSurfaceOperations,
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
	assertStatus("/ops/identity-portability/exports", http.StatusNoContent)
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
	if status := decode("/ops/identity-portability/imports"); status != http.StatusBadRequest {
		t.Fatalf("operations oversized body status=%d", status)
	}

	public := surfaceOnly(routeSurfacePublic, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for path, want := range map[string]int{"/browser/auth/login": http.StatusNoContent, "/identity/users": http.StatusNotFound, "/ops/identity-portability/exports": http.StatusNotFound} {
		response := httptest.NewRecorder()
		public.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != want {
			t.Fatalf("public listener %s status=%d want=%d", path, response.Code, want)
		}
	}
}
