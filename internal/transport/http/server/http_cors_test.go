package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
)

func TestHTTPMiddlewareUsesConfiguredCORSOrigins(t *testing.T) {
	var observedRequestID string
	support := newHTTPSupport(nil, []string{"https://admin.example.com"})
	support.initializedWorkspaceID = "workspace-primary"
	handler := support.middleware(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		observedRequestID = requestcontext.RequestID(request.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	allowed := httptest.NewRequest(http.MethodGet, "http://identity.example.test/health", nil)
	allowed.Header.Set("Origin", "https://admin.example.com")
	allowed.Header.Set("X-Request-ID", "4bf92f3577b34da6a3ce929d0e0e4736")
	allowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowedResponse, allowed)
	if got := allowedResponse.Header().Get("Access-Control-Allow-Origin"); got != "https://admin.example.com" {
		t.Fatalf("allowed origin header = %q", got)
	}
	if got := allowedResponse.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("allow credentials header = %q", got)
	}
	if !strings.Contains(strings.ToLower(allowedResponse.Header().Get("Access-Control-Allow-Headers")), "x-request-id") {
		t.Fatalf("caller-selected trace ID is not accepted by CORS: %q", allowedResponse.Header().Get("Access-Control-Allow-Headers"))
	}
	if observedRequestID != "4bf92f3577b34da6a3ce929d0e0e4736" || allowedResponse.Header().Get("X-Request-ID") != observedRequestID {
		t.Fatalf("trace identity observed=%q response=%q", observedRequestID, allowedResponse.Header().Get("X-Request-ID"))
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
