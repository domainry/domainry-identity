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
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity.db")
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")

	identityServer, err := httpserver.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityServer.CloseContext(t.Context()) })
	testServer := httptest.NewServer(identityServer.Routes())
	t.Cleanup(testServer.Close)

	login := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/login", `{"workspace_id":"default","login":"admin@example.com","password":"Domainry@2026"}`, nil)
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.StatusCode, readResponseBody(t, login))
	}
	var loginPayload map[string]any
	if err := json.NewDecoder(login.Body).Decode(&loginPayload); err != nil {
		t.Fatal(err)
	}
	_ = login.Body.Close()
	if _, exposed := loginPayload["refresh_token"]; exposed {
		t.Fatalf("refresh credential exposed in JSON: %#v", loginPayload)
	}
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
	if _, exposed := refreshPayload["refresh_token"]; exposed {
		t.Fatalf("rotated refresh credential exposed in JSON: %#v", refreshPayload)
	}

	unsafe := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/refresh", `{"refresh_token":"javascript-secret"}`, rotated[0])
	if unsafe.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsafe refresh status=%d body=%s", unsafe.StatusCode, readResponseBody(t, unsafe))
	}
	_ = unsafe.Body.Close()

	invalid := browserRequest(t, testServer.Client(), http.MethodPost, testServer.URL+"/browser/auth/login", `{"workspace_id":"default","login":"admin@example.com","password":"wrong"}`, nil)
	if invalid.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid login status=%d body=%s", invalid.StatusCode, readResponseBody(t, invalid))
	}
	_ = invalid.Body.Close()
}

func browserRequest(t *testing.T, client *http.Client, method, target, body string, cookie *http.Cookie) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Workspace-ID", "default")
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
