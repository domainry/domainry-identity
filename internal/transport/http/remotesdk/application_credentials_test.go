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
		"workspace-a/orders-runtime": "orders-service-secret",
		"workspace-b/notify-runtime": "notify-service-secret",
	}, map[string][]string{"workspace-a/orders-runtime": {"application:orders-runtime"}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	orders := identitysdk.ApplicationScope{WorkspaceID: "workspace-a", ApplicationKey: "orders-runtime"}
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
		"missing workspace": {ApplicationKey: "orders-runtime"},
		"wrong workspace":   {WorkspaceID: "workspace-b", ApplicationKey: "orders-runtime"},
		"wrong application": {WorkspaceID: "workspace-a", ApplicationKey: "notify-runtime"},
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

func TestApplicationCredentialRegistryUsesWorkspaceAndApplication(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{"workspace-primary/orders-runtime": "service-secret"}, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	scope := identitysdk.ApplicationScope{WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime"}
	if decision := registry.Authorize("Bearer service-secret", scope); !decision.Authenticated || decision.RateLimited {
		t.Fatal("explicit workspace application scope was rejected")
	}
}

func TestApplicationCredentialRegistryParsesEscapedIdentifiersAndRejectsInvalidConfiguration(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{"workspace%2Fone/app%2Fone": "service-secret"}, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if decision := registry.Authorize("Bearer service-secret", identitysdk.ApplicationScope{WorkspaceID: "workspace/one", ApplicationKey: "app/one"}); !decision.Authenticated || decision.RateLimited {
		t.Fatal("escaped scope identifiers were not decoded")
	}
	for name, values := range map[string]map[string]string{
		"three segments":          {"tenant-a/workspace-a/orders-runtime": "secret"},
		"duplicate decoded scope": {"workspace-a/orders-runtime#blue": "secret-1", "workspace-a/orders-runtime#%62lue": "secret-2"},
		"missing segment":         {"workspace-only": "secret"},
		"too many segments":       {"tenant/workspace/application/extra": "secret"},
		"empty credential ID":     {"workspace-primary/orders-runtime#": "secret"},
		"empty credential":        {"workspace-primary/orders-runtime": " "},
		"duplicate credential":    {"workspace-primary/orders-runtime": "same", "workspace-primary/notify-runtime": "same"},
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

func TestApplicationCredentialRegistryCapsServiceTokenAudienceAndGrants(t *testing.T) {
	application := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime"}
	registry, err := NewApplicationCredentialRegistry(
		map[string]string{"workspace-primary/orders-runtime": "service-secret"}, nil, 100,
		map[string][]string{"workspace-primary/orders-runtime": {"audience:notification-runtime", "grant:notification_event.publish", "grant:notification_event.read"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	allowed := identitysdk.ExchangeApplicationServiceTokenRequest{
		Application: application, Audience: "notification-runtime",
		Grants: []identitysdk.ApplicationServiceGrant{{Resource: "notification_event", Action: "publish"}},
	}
	if decision := registry.AuthorizeApplicationServiceRequest("Bearer service-secret", allowed); !decision.Authenticated || !decision.ServicePolicyAllowed || decision.RateLimited {
		t.Fatalf("allowed service request = %+v", decision)
	}
	wrongAudience := allowed
	wrongAudience.Audience = "report-runtime"
	if decision := registry.AuthorizeApplicationServiceRequest("Bearer service-secret", wrongAudience); !decision.Authenticated || decision.ServicePolicyAllowed {
		t.Fatalf("unregistered audience escaped policy = %+v", decision)
	}
	wrongGrant := allowed
	wrongGrant.Grants = []identitysdk.ApplicationServiceGrant{{Resource: "notification_event", Action: "delete"}}
	if decision := registry.AuthorizeApplicationServiceRequest("Bearer service-secret", wrongGrant); !decision.Authenticated || decision.ServicePolicyAllowed {
		t.Fatalf("unregistered grant escaped policy = %+v", decision)
	}
}

func TestGlobalApplicationServiceCredentialScopesTokensByWorkspaceAndPolicy(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = registry.ConfigureGlobalApplicationServices(
		map[string]string{"verdent-knowledge#global-index": "global-knowledge-secret"},
		map[string][]string{"verdent-knowledge": {"audience:domainry-runtime", "grant:enterprise.knowledge.index_target"}},
	); err != nil {
		t.Fatal(err)
	}
	registry.clock = func() time.Time { return time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC) }
	request := identitysdk.ExchangeApplicationServiceTokenRequest{
		Application: identitysdk.ApplicationRef{WorkspaceID: "workspace-a", ApplicationKey: "verdent-knowledge"},
		Audience:    "domainry-runtime", Grants: []identitysdk.ApplicationServiceGrant{{Resource: "enterprise.knowledge", Action: "index_target"}},
	}
	decision := registry.AuthorizeApplicationServiceRequest("Bearer global-knowledge-secret", request)
	if !decision.Authenticated || !decision.ServicePolicyAllowed || decision.RateLimited || decision.WorkspaceID != "workspace-a" || decision.CredentialID != "global-index" {
		t.Fatalf("workspace-a decision=%+v", decision)
	}
	if !registry.Active(identitysdk.ApplicationScope{WorkspaceID: "workspace-a", ApplicationKey: "verdent-knowledge"}, "global-index") {
		t.Fatal("issued global credential ID was not active for resource verification")
	}
	if decision = registry.AuthorizeApplicationServiceRequest("Bearer global-knowledge-secret", request); !decision.Authenticated || !decision.RateLimited {
		t.Fatalf("workspace-a rate limit=%+v", decision)
	}
	request.Application.WorkspaceID = "workspace-b"
	if decision = registry.AuthorizeApplicationServiceRequest("Bearer global-knowledge-secret", request); !decision.Authenticated || !decision.ServicePolicyAllowed || decision.RateLimited {
		t.Fatalf("workspace-b shared rate bucket or rejected=%+v", decision)
	}
	request.Audience = "other-runtime"
	if decision = registry.AuthorizeApplicationServiceRequest("Bearer global-knowledge-secret", request); !decision.Authenticated || decision.ServicePolicyAllowed {
		t.Fatalf("global credential escaped audience policy=%+v", decision)
	}
}

func TestGlobalApplicationServiceCredentialRejectsScopedSecretReuse(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{"workspace-a/verdent-knowledge": "reused-secret"}, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	err = registry.ConfigureGlobalApplicationServices(
		map[string]string{"verdent-knowledge#global-index": "reused-secret"},
		map[string][]string{"verdent-knowledge": {"audience:domainry-runtime", "grant:enterprise.knowledge.index_target"}},
	)
	if err == nil {
		t.Fatal("scoped application secret was reused as a global credential")
	}
}

func TestApplicationCredentialRegistryResolvesGlobalVerifierByUniqueResourceCredential(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(map[string]string{
		"workspace-primary/domainry-notification": "notification-secret",
		"workspace-other/domainry-notification":   "other-notification-secret",
	}, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	decision := registry.AuthorizeAudience("Bearer notification-secret", "domainry-notification")
	if !decision.Authenticated || decision.RateLimited || decision.WorkspaceID != "workspace-primary" || decision.ApplicationKey != "domainry-notification" {
		t.Fatalf("global verifier decision = %+v", decision)
	}
	if decision := registry.AuthorizeAudience("Bearer notification-secret", "other-runtime"); decision.Authenticated {
		t.Fatalf("credential escaped its resource audience: %+v", decision)
	}
	if decision := registry.AuthorizeAudience("Bearer unknown-secret", "domainry-notification"); decision.Authenticated {
		t.Fatalf("unknown credential authenticated: %+v", decision)
	}
}

func TestApplicationCredentialRegistryAuthorizesGlobalResourceVerifier(t *testing.T) {
	registry, err := NewApplicationCredentialRegistry(nil, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = registry.ConfigureGlobalApplicationServices(
		map[string]string{"verdent-knowledge#global-service": "global-knowledge-secret"},
		map[string][]string{"verdent-knowledge": {"audience:domainry-runtime", "grant:enterprise.knowledge.index_target"}},
	); err != nil {
		t.Fatal(err)
	}
	decision := registry.AuthorizeAudience("Bearer global-knowledge-secret", "verdent-knowledge")
	if !decision.Authenticated || !decision.Global || decision.RateLimited || decision.WorkspaceID != "" || decision.ApplicationKey != "verdent-knowledge" || decision.CredentialID != "global-service" {
		t.Fatalf("global verifier decision=%+v", decision)
	}
	if escaped := registry.AuthorizeAudience("Bearer global-knowledge-secret", "other-application"); escaped.Authenticated {
		t.Fatalf("global verifier escaped its audience: %+v", escaped)
	}
}

func TestApplicationCredentialRegistryRejectsInvalidServicePolicies(t *testing.T) {
	credentials := map[string]string{"workspace-primary/orders-runtime": "service-secret"}
	for name, policies := range map[string]map[string][]string{
		"orphan scope": {"workspace-primary/other-runtime": {"audience:notification-runtime"}},
		"empty policy": {"workspace-primary/orders-runtime": nil},
		"bad audience": {"workspace-primary/orders-runtime": {"audience:Notification Runtime"}},
		"bad grant":    {"workspace-primary/orders-runtime": {"grant:notification_event"}},
		"bad kind":     {"workspace-primary/orders-runtime": {"role:administrator"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewApplicationCredentialRegistry(credentials, nil, 100, policies); err == nil {
				t.Fatal("invalid application service policy configuration was accepted")
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
	firstRequest := httptest.NewRequest(http.MethodPost, "/identity/users/query", nil)
	firstRequest.Header.Set("Authorization", "Bearer orders-service-secret")
	if !authorizeApplicationCredential(httptest.NewRecorder(), firstRequest, support, registry, scope) {
		t.Fatal("first request was rejected")
	}
	secondRequest := httptest.NewRequest(http.MethodPost, "/identity/users/query", nil)
	secondRequest.Header.Set("Authorization", "Bearer orders-service-secret")
	response := httptest.NewRecorder()
	if authorizeApplicationCredential(response, secondRequest, support, registry, scope) {
		t.Fatal("over-limit request was accepted")
	}
	if response.Code != http.StatusTooManyRequests || response.Body.String() != "identity.application_rate_limited" || response.Header().Get("Retry-After") == "" || response.Header().Get("X-RateLimit-Reset") == "" {
		t.Fatalf("rate-limit response status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}
