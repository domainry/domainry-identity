package httpserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/domainry/domainry-identity/internal/platform/config"
	httpserver "github.com/domainry/domainry-identity/internal/transport/http/server"
)

func TestIdentityAdminBrowserGatewayRotatesHTTPOnlyRefreshCookie(t *testing.T) {
	testServer := newBrowserIdentityTestServer(t)

	login := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/login", `{"workspace_id":"workspace-primary","login":"admin@example.com","password":"Domainry@2026"}`, nil)
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.StatusCode, readResponseBody(t, login))
	}
	var loginPayload map[string]any
	if err := json.NewDecoder(login.Body).Decode(&loginPayload); err != nil {
		t.Fatal(err)
	}
	_ = login.Body.Close()
	assertBrowserPayloadHasNoLegacyCredentials(t, loginPayload)
	cookies := login.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "domainry_identity_refresh" || !cookies[0].HttpOnly || cookies[0].Path != "/browser/auth" || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("login cookies=%#v", cookies)
	}
	firstRefresh := cookies[0].Value

	refresh := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/refresh", `{}`, cookies[0])
	if refresh.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refresh.StatusCode, readResponseBody(t, refresh))
	}
	var refreshPayload map[string]any
	if err := json.NewDecoder(refresh.Body).Decode(&refreshPayload); err != nil {
		t.Fatal(err)
	}
	_ = refresh.Body.Close()
	rotated := refresh.Cookies()
	if len(rotated) != 1 || rotated[0].Value == "" || rotated[0].Value == firstRefresh {
		t.Fatalf("refresh cookie did not rotate: before=%q after=%#v", firstRefresh, rotated)
	}
	assertBrowserPayloadHasNoLegacyCredentials(t, refreshPayload)

	reused := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/refresh", `{}`, &http.Cookie{Name: cookies[0].Name, Value: firstRefresh})
	if reused.StatusCode != http.StatusForbidden {
		t.Fatalf("reused refresh status=%d body=%s", reused.StatusCode, readResponseBody(t, reused))
	}
	reusedCookies := reused.Cookies()
	if len(reusedCookies) != 1 || reusedCookies[0].MaxAge >= 0 {
		t.Fatalf("reused refresh cookie was not cleared: %#v", reusedCookies)
	}
	_ = reused.Body.Close()

	unsafe := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/refresh", `{"refresh_token":"javascript-secret"}`, rotated[0])
	if unsafe.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsafe refresh status=%d body=%s", unsafe.StatusCode, readResponseBody(t, unsafe))
	}
	_ = unsafe.Body.Close()

	legacyTenant := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/refresh", `{"tenant_id":"legacy"}`, rotated[0])
	if legacyTenant.StatusCode != http.StatusBadRequest {
		t.Fatalf("legacy tenant refresh status=%d body=%s", legacyTenant.StatusCode, readResponseBody(t, legacyTenant))
	}
	_ = legacyTenant.Body.Close()

	invalid := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/login", `{"workspace_id":"workspace-primary","login":"admin@example.com","password":"wrong"}`, nil)
	if invalid.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid login status=%d body=%s", invalid.StatusCode, readResponseBody(t, invalid))
	}
	_ = invalid.Body.Close()
}

func TestIdentityAdminBrowserGatewayLogoutRevokesAndClearsRefreshCookie(t *testing.T) {
	testServer := newBrowserIdentityTestServer(t)
	login := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/login", `{"workspace_id":"workspace-primary","login":"admin@example.com","password":"Domainry@2026"}`, nil)
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.StatusCode, readResponseBody(t, login))
	}
	cookies := login.Cookies()
	_ = login.Body.Close()
	if len(cookies) != 1 {
		t.Fatalf("login cookies=%#v", cookies)
	}

	logout := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/logout", `{}`, cookies[0])
	if logout.StatusCode != http.StatusNoContent || logout.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("logout status=%d cache-control=%q", logout.StatusCode, logout.Header.Get("Cache-Control"))
	}
	cleared := logout.Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 || !cleared[0].HttpOnly || cleared[0].Path != "/browser/auth" || cleared[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("logout cookie=%#v", cleared)
	}
	_ = logout.Body.Close()

	retry := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/refresh", `{}`, cookies[0])
	if retry.StatusCode != http.StatusForbidden {
		t.Fatalf("refresh after logout status=%d body=%s", retry.StatusCode, readResponseBody(t, retry))
	}
	retryCookies := retry.Cookies()
	if len(retryCookies) != 1 || retryCookies[0].MaxAge >= 0 {
		t.Fatalf("revoked refresh cookie was not cleared: %#v", retryCookies)
	}
	_ = retry.Body.Close()
}

func newBrowserIdentityTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")

	identityServer, err := httpserver.New(t.Context(), cfg, testServerAssemblyOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityServer.CloseContext(t.Context()) })
	testServer := httptest.NewServer(identityServer.Routes())
	t.Cleanup(testServer.Close)
	return testServer
}

func assertBrowserPayloadHasNoLegacyCredentials(t *testing.T, payload map[string]any) {
	t.Helper()
	if _, exposed := payload["refresh_token"]; exposed {
		t.Fatalf("refresh credential exposed in JSON: %#v", payload)
	}
	if _, exposed := payload["tenant_id"]; exposed {
		t.Fatalf("legacy tenant scope exposed in JSON: %#v", payload)
	}
}

func browserRequest(t *testing.T, client *http.Client, method, target, body string, cookie *http.Cookie) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Workspace-ID", "workspace-primary")
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readResponseBody(t *testing.T, response *http.Response) string {
	t.Helper()
	var payload any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return err.Error()
	}
	_ = response.Body.Close()
	encoded, _ := json.Marshal(payload)
	return string(encoded)
}
