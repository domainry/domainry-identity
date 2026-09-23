package httpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-identity-sdk/browsergateway"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
	authhttp "github.com/domainry/domainry-identity/internal/transport/http/auth"
)

func TestStandaloneRouteInventoryBaseline(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity-route-inventory.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	server, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseContext(t.Context()) })
	routes := server.RouteInventory()
	sum := sha256.Sum256([]byte(strings.Join(routes, "\n")))
	const wantCount = 155
	const wantSHA256 = "a72e833613efe0910328c7da63158b5a2984b1fdd47c28b16b5de5160994dce4"
	if len(routes) != wantCount || hex.EncodeToString(sum[:]) != wantSHA256 {
		t.Fatalf("standalone route inventory count=%d sha256=%s routes=%#v", len(routes), hex.EncodeToString(sum[:]), routes)
	}
}

func TestStandaloneRouteInventoryAndFrozenActionRegistryAreBidirectionallyComplete(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity-route-action-coverage.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	server, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseContext(t.Context()) })

	routes := make(map[string]bool, len(server.RouteInventory()))
	for _, pattern := range server.RouteInventory() {
		method, routeTemplate, found := strings.Cut(pattern, " ")
		if !found {
			t.Fatalf("route inventory contains malformed pattern %q", pattern)
		}
		action, resolved := server.actions.ResolveHTTP(method, routeTemplate)
		if !resolved {
			t.Fatalf("route %q has no frozen ActionDefinition", pattern)
		}
		if action.Authorization.Strategy == "" {
			t.Fatalf("route %q Action %q has no authorization strategy", pattern, action.Key)
		}
		wantExposure := actioncontract.ExposureManagement
		switch controlClassOf(server.exposures.listenerClassesForPattern(method, routeTemplate)) {
		case listenerClassPublic:
			wantExposure = actioncontract.ExposurePublic
		case listenerClassOperations:
			wantExposure = actioncontract.ExposureOps
		}
		exposed := false
		for _, exposure := range action.Exposures {
			if exposure == wantExposure {
				exposed = true
				break
			}
		}
		if !exposed {
			t.Fatalf("route %q classified as %q but Action %q exposures=%v", pattern, wantExposure, action.Key, action.Exposures)
		}
		routes[pattern] = true
	}
	for _, action := range server.actions.Definitions() {
		if action.HTTP == nil {
			continue
		}
		pattern := action.HTTP.Method + " " + action.HTTP.RouteTemplate
		if !routes[pattern] {
			t.Fatalf("HTTP Action %q is not mounted by the standalone server: %q", action.Key, pattern)
		}
	}
}

func TestRecordingRouteRegistrarRejectsRouteOutsideFrozenActionRegistry(t *testing.T) {
	definitions, err := standaloneProtocolAuthorizationActions()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := identityapplication.NewIdentityActionRegistry(definitions)
	if err != nil {
		t.Fatal(err)
	}
	registrar := newRecordingRouteRegistrar(http.NewServeMux(), registry)
	registrar.HandleFunc("GET /unregistered", func(http.ResponseWriter, *http.Request) {})
	if registrar.err == nil || !strings.Contains(registrar.err.Error(), "no ActionDefinition") {
		t.Fatalf("registration error=%v", registrar.err)
	}
	if len(registrar.patterns) != 0 {
		t.Fatalf("rejected route was recorded: %#v", registrar.patterns)
	}
}

func TestEmbeddedAuthRouteInventoryOwnsEveryNonBrowserRoute(t *testing.T) {
	authRoutes := &recordingRouteRegistrar{mux: http.NewServeMux()}
	authhttp.NewAuthHandler(authhttp.AuthDependencies{}).RegisterRoutes(authRoutes)
	browserRoutes, err := browsergateway.RoutePatterns("")
	if err != nil {
		t.Fatal(err)
	}
	resolver := testStandaloneExposureResolver(t)
	publicRoutes, managementRoutes := embeddedAuthRouteInventory(resolver, authRoutes.patterns, browserRoutes)
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

func TestRouteExposureResolverUsesActionExposure(t *testing.T) {
	resolver := testStandaloneExposureResolver(t)
	tests := map[string]listenerClass{
		"GET /browser/auth/login":                 listenerClassPublic,
		"GET /identity/discovery":                 listenerClassPublic,
		"GET /identity/users":                     listenerClassManagement,
		"GET /identity/schema":                    listenerClassManagement,
		"PUT /auth/providers/{provider}/setup":    listenerClassManagement,
		"POST /identity/portability/write-fences": listenerClassOperations,
	}
	for requestTarget, want := range tests {
		method, path, _ := strings.Cut(requestTarget, " ")
		if got := resolver.controlClass(httptest.NewRequest(method, path, nil)); got != want {
			t.Fatalf("classify %q=%q want=%q", requestTarget, got, want)
		}
	}
}

func TestHTTPControlsApplyIndependentRateLimitsAndTimeout(t *testing.T) {
	support := newHTTPSupport(nil, nil, httpControlConfig{
		PublicMaxJSONBodyBytes: 128, ManagementMaxJSONBodyBytes: 128, OperationsMaxJSONBodyBytes: 16,
		PublicRequestTimeout: time.Minute, ManagementRequestTimeout: time.Minute, OperationsRequestTimeout: time.Second,
		PublicRateLimitPerMinute: 1, ManagementRateLimitPerMinute: 1, OperationsRateLimitPerMinute: 1,
	})
	support.initializedWorkspaceID = "workspace-primary"
	support.exposures = testStandaloneExposureResolver(t)
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	support.controls.clock = func() time.Time { return now }
	handler := support.middleware(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if support.exposures.controlClass(request) == listenerClassOperations {
			deadline, ok := request.Context().Deadline()
			if !ok || time.Until(deadline) > 2*time.Second {
				t.Errorf("operations request deadline=%v ok=%v", deadline, ok)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	assertStatus := func(method, path string, want int) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, path, nil))
		if response.Code != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.Code, want, response.Body.String())
		}
	}
	assertStatus(http.MethodGet, "/health", http.StatusNoContent)
	assertStatus(http.MethodGet, "/health", http.StatusTooManyRequests)
	assertStatus(http.MethodGet, "/identity/users", http.StatusNoContent)
	assertStatus(http.MethodPost, "/identity/portability/write-fences", http.StatusNoContent)
}

func TestHTTPControlsApplySurfaceBodyLimitsAndListenerIsolation(t *testing.T) {
	support := newHTTPSupport(nil, nil, httpControlConfig{PublicMaxJSONBodyBytes: 128, OperationsMaxJSONBodyBytes: 8})
	support.exposures = testStandaloneExposureResolver(t)
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
	if status := decode("/identity/portability/write-fences"); status != http.StatusBadRequest {
		t.Fatalf("operations oversized body status=%d", status)
	}

	public := listenerOnly(listenerClassPublic, support.exposures, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for requestTarget, want := range map[string]int{"POST /browser/auth/login": http.StatusNoContent, "GET /identity/users": http.StatusNotFound, "POST /identity/portability/write-fences": http.StatusNotFound} {
		method, path, _ := strings.Cut(requestTarget, " ")
		response := httptest.NewRecorder()
		public.ServeHTTP(response, httptest.NewRequest(method, path, nil))
		if response.Code != want {
			t.Fatalf("public listener %s status=%d want=%d", path, response.Code, want)
		}
	}
}

func testStandaloneExposureResolver(t *testing.T) *routeExposureResolver {
	t.Helper()
	definitions := identityapplication.IdentityBuiltinAuthorizationActions()
	protocol, err := standaloneProtocolAuthorizationActions()
	if err != nil {
		t.Fatal(err)
	}
	definitions = append(definitions, protocol...)
	browser, err := browsergateway.ActionDefinitions("/browser")
	if err != nil {
		t.Fatal(err)
	}
	definitions = append(definitions, browser...)
	registry, err := identityapplication.NewIdentityActionRegistry(definitions)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	for _, definition := range registry.Definitions() {
		if definition.HTTP != nil {
			mux.Handle(definition.HTTP.Method+" "+definition.HTTP.RouteTemplate, http.NotFoundHandler())
		}
	}
	return newRouteExposureResolver(mux, registry)
}
