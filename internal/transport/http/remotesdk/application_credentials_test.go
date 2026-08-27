package remotesdk

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

func TestApplicationCredentialRegistryAuthorizesOnlyItsBoundScope(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{
		"tenant-a/workspace-a/orders-runtime": "orders-service-secret",
		"workspace-b/notify-runtime":          "notify-service-secret",
	}, 100)
	if err != nil {
		t.Fatal(err)
	}
	orders := identitysdk.ApplicationScope{TenantID: "tenant-a", WorkspaceID: "workspace-a", ApplicationKey: "orders-runtime"}
	if decision := registry.Authorize("Bearer orders-service-secret", orders); !decision.Authenticated || decision.RateLimited {
		t.Fatal("matching application credential was rejected")
	}
	for name, scope := range map[string]identitysdk.ApplicationScope{
		"wrong tenant":      {TenantID: "tenant-b", WorkspaceID: "workspace-a", ApplicationKey: "orders-runtime"},
		"wrong workspace":   {TenantID: "tenant-a", WorkspaceID: "workspace-b", ApplicationKey: "orders-runtime"},
		"wrong application": {TenantID: "tenant-a", WorkspaceID: "workspace-a", ApplicationKey: "notify-runtime"},
	} {
		t.Run(name, func(t *testing.T) {
			if registry.Authorize("Bearer orders-service-secret", scope).Authenticated {
				t.Fatal("credential escaped its configured application scope")
			}
		})
	}
	if registry.Authorize("Bearer notify-service-secret", orders).Authenticated {
		t.Fatal("another application's credential was accepted")
	}
	for _, authorization := range []string{"", "Basic orders-service-secret", "Bearer", "Bearer wrong-secret"} {
		if registry.Authorize(authorization, orders).Authenticated {
			t.Fatalf("authorization %q accepted", authorization)
		}
	}
}

func TestApplicationCredentialRegistryDefaultsTenantToWorkspace(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{"default/orders-runtime": "service-secret"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	scope := identitysdk.ApplicationScope{WorkspaceID: "default", ApplicationKey: "orders-runtime"}
	if decision := registry.Authorize("Bearer service-secret", scope); !decision.Authenticated || decision.RateLimited {
		t.Fatal("workspace shorthand did not bind tenant to workspace")
	}
}

func TestApplicationCredentialRegistryParsesEscapedIdentifiersAndRejectsInvalidConfiguration(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{"tenant%2Fone/workspace%2Fone/app%2Fone": "service-secret"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if decision := registry.Authorize("Bearer service-secret", identitysdk.ApplicationScope{TenantID: "tenant/one", WorkspaceID: "workspace/one", ApplicationKey: "app/one"}); !decision.Authenticated || decision.RateLimited {
		t.Fatal("escaped scope identifiers were not decoded")
	}
	for name, values := range map[string]map[string]string{
		"missing segment":      {"workspace-only": "secret"},
		"too many segments":    {"tenant/workspace/application/extra": "secret"},
		"empty credential ID":  {"default/orders-runtime#": "secret"},
		"empty credential":     {"default/orders-runtime": " "},
		"duplicate credential": {"default/orders-runtime": "same", "default/notify-runtime": "same"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewApplicationCredentialRegistry(values, 100); err == nil {
				t.Fatal("invalid application service credential configuration was accepted")
			}
		})
	}
}

func TestApplicationCredentialRotationSharesOneApplicationRateBucket(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{
		"default/orders-runtime#old": "old-service-secret",
		"default/orders-runtime#new": "new-service-secret",
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	registry.clock = func() time.Time { return time.Date(2026, 8, 27, 4, 30, 0, 0, time.UTC) }
	scope := identitysdk.ApplicationScope{WorkspaceID: "default", ApplicationKey: "orders-runtime"}
	if decision := registry.Authorize("Bearer old-service-secret", scope); !decision.Authenticated || decision.RateLimited {
		t.Fatalf("old credential=%+v", decision)
	}
	if decision := registry.Authorize("Bearer new-service-secret", scope); !decision.Authenticated || decision.RateLimited {
		t.Fatalf("new credential=%+v", decision)
	}
	if decision := registry.Authorize("Bearer new-service-secret", scope); !decision.Authenticated || !decision.RateLimited {
		t.Fatalf("rotation credentials did not share one application bucket: %+v", decision)
	}
}

func TestApplicationCredentialRateLimitsAreIndependentPerApplication(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{
		"default/orders-runtime": "orders-service-secret",
		"default/notify-runtime": "notify-service-secret",
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	registry.clock = func() time.Time { return time.Date(2026, 8, 27, 4, 30, 0, 0, time.UTC) }
	orders := identitysdk.ApplicationScope{WorkspaceID: "default", ApplicationKey: "orders-runtime"}
	if decision := registry.Authorize("Bearer orders-service-secret", orders); !decision.Authenticated || decision.RateLimited || decision.Remaining != 0 {
		t.Fatalf("first orders request=%+v", decision)
	}
	if decision := registry.Authorize("Bearer orders-service-secret", orders); !decision.Authenticated || !decision.RateLimited {
		t.Fatalf("second orders request=%+v", decision)
	}
	notify := identitysdk.ApplicationScope{WorkspaceID: "default", ApplicationKey: "notify-runtime"}
	if decision := registry.Authorize("Bearer notify-service-secret", notify); !decision.Authenticated || decision.RateLimited {
		t.Fatalf("notify request shared the orders rate bucket: %+v", decision)
	}
}

func TestApplicationCredentialHTTPBoundaryReturnsRateLimitResponse(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{"default/orders-runtime": "orders-service-secret"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	registry.clock = func() time.Time { return time.Date(2026, 8, 27, 4, 30, 0, 0, time.UTC) }
	support := Support{WriteError: func(w http.ResponseWriter, _ *http.Request, status int, code string, _ ...string) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(code))
	}}
	scope := identitysdk.ApplicationScope{WorkspaceID: "default", ApplicationKey: "orders-runtime"}
	firstRequest := httptest.NewRequest(http.MethodPost, "/identity/runtime/directory/users", nil)
	firstRequest.Header.Set("Authorization", "Bearer orders-service-secret")
	if !authorizeApplicationCredential(httptest.NewRecorder(), firstRequest, support, registry, scope) {
		t.Fatal("first request was rejected")
	}
	secondRequest := httptest.NewRequest(http.MethodPost, "/identity/runtime/directory/users", nil)
	secondRequest.Header.Set("Authorization", "Bearer orders-service-secret")
	response := httptest.NewRecorder()
	if authorizeApplicationCredential(response, secondRequest, support, registry, scope) {
		t.Fatal("over-limit request was accepted")
	}
	if response.Code != http.StatusTooManyRequests || response.Body.String() != "identity.application_rate_limited" || response.Header().Get("Retry-After") == "" || response.Header().Get("X-RateLimit-Reset") == "" {
		t.Fatalf("rate-limit response status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}
