package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthRoutesBindMethodsAndPaths(t *testing.T) {
	handler := NewAuthHandler(AuthDependencies{Admin: func(next http.HandlerFunc) http.HandlerFunc { return next }})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodPatch, "/auth/login", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method route status=%d", response.Code)
	}
}

func TestAuthProviderSetupUsesAuthenticatedOwnerPermissionBoundary(t *testing.T) {
	handler := NewAuthHandler(AuthDependencies{
		Admin: func(http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }
		},
		Authenticated: func(http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
		},
	})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/auth/providers/oidc/setup", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("provider setup still uses Admin Console wrapper: status=%d", response.Code)
	}
}
