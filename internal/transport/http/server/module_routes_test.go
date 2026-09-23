package httpserver_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulehttp"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
	httpserver "github.com/domainry/domainry-identity/internal/transport/http/server"
)

type testModuleHTTPProvider struct {
	actions  []actioncontract.ActionDefinition
	adapters []modulehttp.Adapter
}

type testModuleActionProvider struct {
	actions []actioncontract.ActionDefinition
}

func (provider testModuleActionProvider) AuthorizationActions() ([]actioncontract.ActionDefinition, error) {
	result := make([]actioncontract.ActionDefinition, len(provider.actions))
	for index := range provider.actions {
		result[index] = actioncontract.CloneDefinition(provider.actions[index])
	}
	return result, nil
}

func (provider testModuleHTTPProvider) AuthorizationActions() ([]actioncontract.ActionDefinition, error) {
	result := make([]actioncontract.ActionDefinition, len(provider.actions))
	for index := range provider.actions {
		result[index] = actioncontract.CloneDefinition(provider.actions[index])
	}
	return result, nil
}

func (provider testModuleHTTPProvider) HTTPAdapters() []modulehttp.Adapter {
	return append([]modulehttp.Adapter(nil), provider.adapters...)
}

type testModuleHTTPAdapter struct {
	owner, name string
	routes      []modulehttp.Route
	handler     http.Handler
}

func (adapter testModuleHTTPAdapter) ContractVersion() string { return modulehttp.ContractVersion }
func (adapter testModuleHTTPAdapter) Owner() string           { return adapter.owner }
func (adapter testModuleHTTPAdapter) Name() string            { return adapter.name }
func (adapter testModuleHTTPAdapter) Handler() http.Handler   { return adapter.handler }
func (adapter testModuleHTTPAdapter) Routes() []modulehttp.Route {
	return append([]modulehttp.Route(nil), adapter.routes...)
}

func TestStandaloneGenericModuleContributionReconcilesBeforeMountAndUsesHostGate(t *testing.T) {
	var handlerCalls atomic.Int64
	provider := inventoryModuleProvider("module:inventory", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	cfg, store := openModuleContributionStore(t)
	server, err := httpserver.NewWithStore(t.Context(), cfg, store, testServerAssemblyOptions(httpserver.ServerAssemblyOptions{ModuleProviders: []actioncontract.Provider{provider}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseContext(t.Context()) })

	var rows int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_permissions WHERE workspace_id = ? AND permission_key = ? AND source_owner = ?`, cfg.IdentityWorkspaceID, "inventory.items.list", "module:inventory").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("generic module permission rows=%d err=%v", rows, err)
	}
	response := httptest.NewRecorder()
	server.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/inventory/items", nil))
	if response.Code != http.StatusUnauthorized || handlerCalls.Load() != 0 {
		t.Fatalf("generic module host gate status=%d handler_calls=%d body=%s", response.Code, handlerCalls.Load(), response.Body.String())
	}
}

func TestStandaloneRejectsModuleActionOwnerMismatchBeforeReady(t *testing.T) {
	provider := inventoryModuleProvider("module:other", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("invalid module adapter was mounted")
	}))
	cfg, store := openModuleContributionStore(t)
	_, err := httpserver.NewWithStore(t.Context(), cfg, store, testServerAssemblyOptions(httpserver.ServerAssemblyOptions{ModuleProviders: []actioncontract.Provider{provider}}))
	if err == nil || !strings.Contains(err.Error(), `owner="module:other" want="module:inventory"`) {
		t.Fatalf("module owner mismatch error=%v", err)
	}
}

func TestStandaloneRejectsModuleHTTPAdapterDriftFromSourceManifest(t *testing.T) {
	provider := inventoryModuleProvider("module:inventory", http.NotFoundHandler())
	adapter := provider.adapters[0].(testModuleHTTPAdapter)
	adapter.routes[0].Action.Label = "Drifted route copy"
	provider.adapters[0] = adapter
	cfg, store := openModuleContributionStore(t)
	_, err := httpserver.NewWithStore(t.Context(), cfg, store, testServerAssemblyOptions(httpserver.ServerAssemblyOptions{ModuleProviders: []actioncontract.Provider{provider}}))
	if err == nil || !strings.Contains(err.Error(), "differs from its source manifest") {
		t.Fatalf("module Action drift error=%v", err)
	}
}

func TestStandaloneReconcilesPureNonHTTPModuleActionAndRejectsUnservedHTTP(t *testing.T) {
	action := inventoryModuleAction("module:inventory")
	action.Key = "inventory.items.rebuild"
	action.OperationKey = "rebuild"
	action.OperationLabel = "Rebuild"
	action.Label = "Rebuild inventory items"
	action.HTTP = nil
	action.NonHTTP = []actioncontract.NonHTTPBinding{{Kind: "job", InvocationKey: "inventory.items.rebuild"}}
	action.Permission.Key = action.Key
	action.Permission.OperationKey = action.OperationKey
	action.Permission.Label = "Inventory items · Rebuild"
	action.EffectClass = actioncontract.EffectWrite
	action.IdempotencyDecision = "natural_key"
	provider := testModuleActionProvider{actions: []actioncontract.ActionDefinition{action}}
	cfg, store := openModuleContributionStore(t)
	server, err := httpserver.NewWithStore(t.Context(), cfg, store, testServerAssemblyOptions(httpserver.ServerAssemblyOptions{ModuleProviders: []actioncontract.Provider{provider}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseContext(t.Context()) })
	var rows int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_permissions WHERE workspace_id = ? AND permission_key = ? AND source_owner = ?`, cfg.IdentityWorkspaceID, action.Key, action.Owner).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("non-HTTP module permission rows=%d err=%v", rows, err)
	}

	unserved := inventoryModuleAction("module:inventory")
	cfg2, store2 := openModuleContributionStore(t)
	_, err = httpserver.NewWithStore(t.Context(), cfg2, store2, testServerAssemblyOptions(httpserver.ServerAssemblyOptions{ModuleProviders: []actioncontract.Provider{testModuleActionProvider{actions: []actioncontract.ActionDefinition{unserved}}}}))
	if err == nil || !strings.Contains(err.Error(), "has no mounted adapter route") {
		t.Fatalf("unserved module HTTP Action error=%v", err)
	}
}

func inventoryModuleProvider(actionOwner string, handler http.Handler) testModuleHTTPProvider {
	action := inventoryModuleAction(actionOwner)
	return testModuleHTTPProvider{actions: []actioncontract.ActionDefinition{action}, adapters: []modulehttp.Adapter{testModuleHTTPAdapter{
		owner: "inventory", name: "product", routes: []modulehttp.Route{{Action: action}}, handler: handler,
	}}}
}

func inventoryModuleAction(actionOwner string) actioncontract.ActionDefinition {
	return actioncontract.ActionDefinition{
		Key: "inventory.items.list", Owner: actionOwner, SourceKind: "module_http",
		CapabilityKey: "inventory.items", CapabilityLabel: "Inventory items", OperationKey: "list", OperationLabel: "List",
		Label: "List inventory items", Exposures: []actioncontract.Exposure{actioncontract.ExposureManagement},
		Authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticated},
		HTTP:          &actioncontract.HTTPBinding{Method: http.MethodGet, RouteTemplate: "/inventory/items"},
		Permission: &actioncontract.PermissionDefinition{
			Key: "inventory.items.list", Owner: actionOwner, ResourceKey: "inventory.items", OperationKey: "list",
			Label: "Inventory items · List", Category: "Inventory", LifecycleStatus: actioncontract.LifecycleActive,
		},
		EffectClass: actioncontract.EffectRead, RiskLevel: actioncontract.RiskLow,
		IdempotencyDecision: "not_applicable", AuditClass: "inventory", LifecycleStatus: actioncontract.LifecycleActive,
	}
}

func openModuleContributionStore(t *testing.T) (config.Config, *database.IdentityStore) {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver = "development", "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity-module-contribution.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, store
}
