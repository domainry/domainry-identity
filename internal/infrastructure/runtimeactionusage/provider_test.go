package runtimeactionusage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type staticTokenSource struct {
	token string
	err   error
}

func (source staticTokenSource) AccessToken(context.Context) (string, error) {
	return source.token, source.err
}

func TestProviderQueriesMultipleOwnersInOneAuthenticatedRequest(t *testing.T) {
	registry := actioncontract.NewRegistry()
	if err := registry.Register(
		testPermissionAction("orders.customers.list", "module:orders", "/orders/customers"),
		testPermissionAction("billing.invoices.get", "module:billing", "/billing/invoices/{invoiceID}"),
	); err != nil {
		t.Fatal(err)
	}
	if err := registry.Freeze(); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/runtime"+queryPath {
			t.Errorf("request=%s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer runtime-service-token" || request.Header.Get("X-Workspace-ID") != "workspace-a" || request.Header.Get("X-Request-ID") != "request-a" {
			t.Errorf("headers=%v", request.Header)
		}
		var query actioncontract.PermissionUsageRequest
		if err := json.NewDecoder(request.Body).Decode(&query); err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		snapshot, err := registry.QueryPermissionUsages(request.Context(), query)
		if err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(snapshot)
	}))
	defer server.Close()
	provider, err := New(Options{RuntimeURL: server.URL + "/runtime/", RequestTimeout: time.Second, TokenSource: staticTokenSource{token: "runtime-service-token"}})
	if err != nil {
		t.Fatal(err)
	}
	query, err := actioncontract.NewPermissionUsageRequest([]actioncontract.PermissionUsageQuery{
		{SourceOwner: "module:orders", PermissionKeys: []string{"orders.customers.list"}},
		{SourceOwner: "module:billing", PermissionKeys: []string{"billing.invoices.get"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-a")
	ctx = requestcontext.WithRequestID(ctx, "request-a")
	ctx = identitysdk.WithRequestIdentity(ctx, identitysdk.RequestIdentity{
		Principal:   identitysdk.Principal{Known: true, WorkspaceID: "workspace-a", UserID: "user-a"},
		AccessToken: " caller-token ",
	})
	snapshot, err := provider.QueryPermissionUsages(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || len(snapshot.Owners) != 2 || !snapshot.Owners[0].Available || !snapshot.Owners[1].Available {
		t.Fatalf("calls=%d snapshot=%#v", calls.Load(), snapshot)
	}
}

func TestProviderFailsClosedOnCallerAndResponseBoundaryErrors(t *testing.T) {
	query, err := actioncontract.NewPermissionUsageRequest([]actioncontract.PermissionUsageQuery{{
		SourceOwner: "module:orders", PermissionKeys: []string{"orders.customers.list"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	validContext := func() context.Context {
		ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-a")
		return identitysdk.WithRequestIdentity(ctx, identitysdk.RequestIdentity{
			Principal: identitysdk.Principal{Known: true, WorkspaceID: "workspace-a", UserID: "user-a"}, AccessToken: "token",
		})
	}
	t.Run("missing caller", func(t *testing.T) {
		provider, newErr := New(Options{RuntimeURL: "https://runtime.example.com", RequestTimeout: time.Second, TokenSource: staticTokenSource{token: "service-token"}})
		if newErr != nil {
			t.Fatal(newErr)
		}
		if _, queryErr := provider.QueryPermissionUsages(t.Context(), query); queryErr == nil {
			t.Fatal("missing caller was accepted")
		}
	})
	t.Run("workspace mismatch", func(t *testing.T) {
		provider, newErr := New(Options{RuntimeURL: "https://runtime.example.com", RequestTimeout: time.Second, TokenSource: staticTokenSource{token: "service-token"}})
		if newErr != nil {
			t.Fatal(newErr)
		}
		ctx := requestcontext.WithWorkspaceID(validContext(), "workspace-b")
		if _, queryErr := provider.QueryPermissionUsages(ctx, query); queryErr == nil {
			t.Fatal("workspace mismatch was accepted")
		}
	})
	for name, handler := range map[string]http.HandlerFunc{
		"non-success": func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusForbidden) },
		"oversized": func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte(strings.Repeat("x", int(maxResponseBytes)+1)))
		},
		"trailing JSON": func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte(`{"contract_version":"domainry-action-permission-usage-v1"} {}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			provider, newErr := New(Options{RuntimeURL: server.URL, RequestTimeout: time.Second, TokenSource: staticTokenSource{token: "service-token"}})
			if newErr != nil {
				t.Fatal(newErr)
			}
			if _, queryErr := provider.QueryPermissionUsages(validContext(), query); queryErr == nil {
				t.Fatalf("%s response was accepted", name)
			}
		})
	}
}

func TestProviderConfigurationRejectsAmbiguousRuntimeURLs(t *testing.T) {
	for _, rawURL := range []string{"", "runtime.internal", "ftp://runtime.internal", "https://user:secret@runtime.internal", "https://runtime.internal?query=1", "https://runtime.internal#fragment"} {
		if _, err := New(Options{RuntimeURL: rawURL, RequestTimeout: time.Second, TokenSource: staticTokenSource{token: "service-token"}}); err == nil {
			t.Fatalf("URL %q was accepted", rawURL)
		}
	}
	if _, err := New(Options{RuntimeURL: "https://runtime.internal", RequestTimeout: 0, TokenSource: staticTokenSource{token: "service-token"}}); err == nil {
		t.Fatal("zero request timeout was accepted")
	}
	if _, err := New(Options{RuntimeURL: "https://runtime.internal", RequestTimeout: time.Second}); err == nil {
		t.Fatal("missing service token source was accepted")
	}
}

func testPermissionAction(key, owner, route string) actioncontract.ActionDefinition {
	resource, operation, _ := strings.Cut(key, ".")
	return actioncontract.ActionDefinition{
		Key: key, Owner: owner, SourceKind: "module_surface", CapabilityKey: resource, CapabilityLabel: resource,
		OperationKey: operation, OperationLabel: key, Label: key, Exposures: []actioncontract.Exposure{actioncontract.ExposureTenantAdmin},
		Authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationExactRolePermission},
		HTTP:          &actioncontract.HTTPBinding{Method: http.MethodGet, RouteTemplate: route},
		Permission: &actioncontract.PermissionDefinition{
			Key: key, Owner: owner, ResourceKey: resource, ActionKey: operation, Label: key, Category: resource, LifecycleStatus: actioncontract.LifecycleActive,
		},
		EffectClass: actioncontract.EffectRead, RiskLevel: actioncontract.RiskLow, IdempotencyDecision: "not_applicable", AuditClass: "test", LifecycleStatus: actioncontract.LifecycleActive,
	}
}
