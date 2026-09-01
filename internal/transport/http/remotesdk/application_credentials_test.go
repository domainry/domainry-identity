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
	}, map[string][]string{"tenant-a/workspace-a/orders-runtime": {"application:orders-runtime"}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	orders := identitysdk.ApplicationScope{TenantID: "tenant-a", WorkspaceID: "workspace-a", ApplicationKey: "orders-runtime"}
	if decision := registry.Authorize("Bearer orders-service-secret", orders); !decision.Authenticated || decision.RateLimited {
		t.Fatal("matching application credential was rejected")
	}
	if decision := registry.AuthorizeSourceOwner("Bearer orders-service-secret", orders, "application:orders-runtime"); !decision.Authenticated || !decision.SourceOwnerAllowed || decision.RateLimited {
		t.Fatalf("configured permission owner scope was rejected: %+v", decision)
	}
	if decision := registry.AuthorizeSourceOwner("Bearer orders-service-secret", orders, "module:notification"); !decision.Authenticated || decision.SourceOwnerAllowed {
		t.Fatalf("credential escaped its permission owner scope: %+v", decision)
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
	registry, err := NewApplicationCredentialRegistry(map[string]string{"workspace-primary/orders-runtime": "service-secret"}, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	scope := identitysdk.ApplicationScope{WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime"}
	if decision := registry.Authorize("Bearer service-secret", scope); !decision.Authenticated || decision.RateLimited {
		t.Fatal("workspace shorthand did not bind tenant to workspace")
	}
}

func TestApplicationCredentialRegistryParsesEscapedIdentifiersAndRejectsInvalidConfiguration(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{"tenant%2Fone/workspace%2Fone/app%2Fone": "service-secret"}, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if decision := registry.Authorize("Bearer service-secret", identitysdk.ApplicationScope{TenantID: "tenant/one", WorkspaceID: "workspace/one", ApplicationKey: "app/one"}); !decision.Authenticated || decision.RateLimited {
		t.Fatal("escaped scope identifiers were not decoded")
	}
	for name, values := range map[string]map[string]string{
		"missing segment":      {"workspace-only": "secret"},
		"too many segments":    {"tenant/workspace/application/extra": "secret"},
		"empty credential ID":  {"workspace-primary/orders-runtime#": "secret"},
		"empty credential":     {"workspace-primary/orders-runtime": " "},
		"duplicate credential": {"workspace-primary/orders-runtime": "same", "workspace-primary/notify-runtime": "same"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewApplicationCredentialRegistry(values, nil, 100); err == nil {
				t.Fatal("invalid application service credential configuration was accepted")
			}
		})
	}
}

func TestApplicationCredentialRegistryRejectsInvalidPermissionOwnerScopes(t *testing.T) {
	credentials := map[string]string{"workspace-primary/orders-runtime": "service-secret"}
	for name, owners := range map[string]map[string][]string{
		"invalid owner": {"workspace-primary/orders-runtime": {"Application Owner"}},
		"orphan scope":  {"workspace-primary/other-runtime": {"application:other-runtime"}},
		"empty owners":  {"workspace-primary/orders-runtime": nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewApplicationCredentialRegistry(credentials, owners, 100); err == nil {
				t.Fatal("invalid application permission owner configuration was accepted")
			}
		})
	}
}

func TestApplicationCredentialRotationSharesOneApplicationRateBucket(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{
		"workspace-primary/orders-runtime#old": "old-service-secret",
		"workspace-primary/orders-runtime#new": "new-service-secret",
	}, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	registry.clock = func() time.Time { return time.Date(2026, 8, 27, 4, 30, 0, 0, time.UTC) }
	scope := identitysdk.ApplicationScope{WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime"}
	if !registry.Active(scope, "old") || !registry.Active(scope, "new") || registry.Active(scope, "retired") {
		t.Fatal("credential rotation IDs were not constrained to active registrations")
	}
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
		"workspace-primary/orders-runtime": "orders-service-secret",
		"workspace-primary/notify-runtime": "notify-service-secret",
	}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	registry.clock = func() time.Time { return time.Date(2026, 8, 27, 4, 30, 0, 0, time.UTC) }
	orders := identitysdk.ApplicationScope{WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime"}
	if decision := registry.Authorize("Bearer orders-service-secret", orders); !decision.Authenticated || decision.RateLimited || decision.Remaining != 0 {
		t.Fatalf("first orders request=%+v", decision)
	}
	if decision := registry.Authorize("Bearer orders-service-secret", orders); !decision.Authenticated || !decision.RateLimited {
		t.Fatalf("second orders request=%+v", decision)
	}
	notify := identitysdk.ApplicationScope{WorkspaceID: "workspace-primary", ApplicationKey: "notify-runtime"}
	if decision := registry.Authorize("Bearer notify-service-secret", notify); !decision.Authenticated || decision.RateLimited {
		t.Fatalf("notify request shared the orders rate bucket: %+v", decision)
	}
}

func TestApplicationCredentialHTTPBoundaryReturnsRateLimitResponse(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{"workspace-primary/orders-runtime": "orders-service-secret"}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	registry.clock = func() time.Time { return time.Date(2026, 8, 27, 4, 30, 0, 0, time.UTC) }
	support := Support{WriteError: func(w http.ResponseWriter, _ *http.Request, status int, code string, _ ...string) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(code))
	}}
	scope := identitysdk.ApplicationScope{WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime"}
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
