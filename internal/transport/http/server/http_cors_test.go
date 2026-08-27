package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPMiddlewareUsesConfiguredCORSOrigins(t *testing.T) {
	handler := newHTTPSupport(nil, []string{"https://admin.example.com"}).middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	allowed := httptest.NewRequest(http.MethodGet, "http://identity.example.test/health", nil)
	allowed.Header.Set("Origin", "https://admin.example.com")
	allowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowedResponse, allowed)
	if got := allowedResponse.Header().Get("Access-Control-Allow-Origin"); got != "https://admin.example.com" {
		t.Fatalf("allowed origin header = %q", got)
	}
	if got := allowedResponse.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("allow credentials header = %q", got)
	}

	denied := httptest.NewRequest(http.MethodOptions, "http://identity.example.test/health", nil)
	denied.Header.Set("Origin", "https://attacker.example.com")
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, denied)
	if got := deniedResponse.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("denied origin was reflected: %q", got)
	}
}

func TestHTTPMiddlewareAllowsConfiguredDevelopmentWildcard(t *testing.T) {
	handler := newHTTPSupport(nil, []string{"*"}).middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodOptions, "http://identity.example.test/health", nil)
	request.Header.Set("Origin", "http://127.0.0.1:3103")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:3103" {
		t.Fatalf("development origin header = %q", got)
	}
}
