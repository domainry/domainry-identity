package module_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityhttpapi "github.com/domainry/domainry-identity-sdk/httpapi"
	identitymodule "github.com/domainry/domainry-identity/module"
)

type testWorkspaceResolver map[identitysdk.WorkspaceID]identitysdk.WorkspaceID

func (r testWorkspaceResolver) ResolveWorkspace(_ context.Context, ref identitysdk.WorkspaceID) (identitysdk.WorkspaceID, error) {
	if id := r[ref]; id != "" {
		return id, nil
	}
	return "", errors.New("unavailable")
}

func TestEmbeddedHostWorkspaceLoginAfterAtomicBootstrap(t *testing.T) {
	initialCatalog := m1WorkspaceBootstrapRoleCatalog()
	initialCatalog.Roles[0].Permissions = []identitysdk.ProjectRolePermission{
		{PermissionKey: "identity.users.list", DataScope: "all"},
		{PermissionKey: "auth.providers.setup", DataScope: "all"},
	}
	bootstrap, db := openWorkspaceIdentityBootstrapCatalog(t, initialCatalog)
	a := workspaceIdentityBootstrapRequest("workspace-primary", "bootstrap-a")
	tx := beginBootstrapTx(t, db)
	receipt, err := bootstrap.BootstrapWorkspaceIdentity(t.Context(), a, identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	completeWorkspaceIdentityBootstrap(t, bootstrap, receipt, identitysdk.WorkspaceIdentityBootstrapTransactionCommitted)
	primaryCredential, err := bootstrap.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: a.WorkspaceID, ReceiptID: receipt.ReceiptID})
	if err != nil {
		t.Fatal(err)
	}
	resolver := testWorkspaceResolver{"public-a": "workspace-primary", "workspace-primary": "workspace-primary", "public-b": "workspace-b", "workspace-b": "workspace-b"}
	binding, err := testIdentityFactory(identitymodule.Options{IdentityVersion: "test", DatabaseDriver: "sqlite"}).OpenWithDatabase(t.Context(), identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime"}, identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", Migrations: &testEmbeddedMigrationRegistrar{}, WorkspaceResolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(context.Background()) })
	installAndBindModuleSharedOperations(t, db, binding)
	catalog := initialCatalog
	catalog.Application = identitysdk.ApplicationRef{ApplicationKey: "runtime"}
	if err := binding.(identitysdk.BootstrapProjectRoleCatalogBinder).BindBootstrapProjectRoleCatalog(t.Context(), catalog); err != nil {
		t.Fatal(err)
	}
	provisioner := binding.(identitysdk.WorkspaceIdentityBootstrap)
	b := workspaceIdentityBootstrapRequest("workspace-b", "bootstrap-b")
	// A duplicate login in B must roll back the application registration and graph.
	duplicate := b
	duplicate.InitialAdminLoginID = "  admin@example.test  "
	rejectedTx := beginBootstrapTx(t, db)
	if _, err := provisioner.BootstrapWorkspaceIdentity(t.Context(), duplicate, identitysdk.EmbeddedTransaction{Executor: rejectedTx}); err == nil {
		_ = rejectedTx.Rollback()
		t.Fatal("duplicate global login accepted")
	}
	if err := rejectedTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertWorkspaceBootstrapZero(t, db, b.WorkspaceID)
	tx = beginBootstrapTx(t, db)
	receipt, err = provisioner.BootstrapWorkspaceIdentity(t.Context(), b, identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := provisioner.CompleteWorkspaceIdentityBootstrap(t.Context(), identitysdk.WorkspaceIdentityBootstrapCompletion{WorkspaceID: b.WorkspaceID, ReceiptID: receipt.ReceiptID, Outcome: identitysdk.WorkspaceIdentityBootstrapTransactionCommitted}); err != nil {
		t.Fatal(err)
	}
	credential, err := provisioner.ClaimWorkspaceIdentityBootstrapCredential(t.Context(), identitysdk.WorkspaceIdentityBootstrapCredentialClaim{WorkspaceID: b.WorkspaceID, ReceiptID: receipt.ReceiptID})
	if err != nil {
		t.Fatal(err)
	}
	assertIdentityRowCount(t, db, "_identity_applications", b.WorkspaceID, 1)
	session, err := binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{WorkspaceID: "public-b", Login: credential.LoginID, Password: credential.InitialPassword})
	if err != nil {
		t.Fatal("canonical login", err)
	}
	if session.WorkspaceID != b.WorkspaceID || !session.MustChangePassword {
		t.Fatal("invalid B session scope")
	}
	session, err = binding.Credentials().ChangePassword(t.Context(), identitysdk.ChangePasswordRequest{AccessToken: session.AccessToken, CurrentPassword: credential.InitialPassword, NewPassword: "Workspace-B-Test-Password!29", IdempotencyKey: "change-b-password"})
	if err != nil {
		t.Fatal("change password", err)
	}
	session, err = binding.Authentication().RefreshSession(t.Context(), identitysdk.RefreshRequest{WorkspaceID: "workspace-b", RefreshToken: session.RefreshToken})
	if err != nil {
		t.Fatal("refresh", err)
	}
	verified, err := binding.Tokens().Verify(t.Context(), identitysdk.VerifyTokenRequest{AccessToken: session.AccessToken})
	if err != nil {
		t.Fatal("token", err)
	}
	principal, err := binding.Principals().Resolve(requestcontext.WithWorkspaceID(t.Context(), string(verified.WorkspaceID)), identitysdk.PrincipalResolutionRequest{SubjectID: verified.SubjectID})
	if err != nil {
		t.Fatal("principal", err)
	}
	if principal.Principal.WorkspaceID != b.WorkspaceID {
		t.Fatal("principal escaped B")
	}
	// Management requests derive scope from the verified bearer, even without
	// an explicit workspace header; conflicting client scope cannot override it.
	mounted := http.NewServeMux()
	for _, adapter := range binding.(identityhttpapi.Provider).HTTPAdapters() {
		for _, route := range adapter.Routes() {
			mounted.Handle(route.Pattern(), adapter.Handler())
		}
	}
	primarySession, err := binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{WorkspaceID: identitysdk.WorkspaceID(a.WorkspaceID), Login: primaryCredential.LoginID, Password: primaryCredential.InitialPassword})
	if err != nil {
		t.Fatal(err)
	}
	primarySession, err = binding.Credentials().ChangePassword(t.Context(), identitysdk.ChangePasswordRequest{AccessToken: primarySession.AccessToken, CurrentPassword: primaryCredential.InitialPassword, NewPassword: "Workspace-A-Test-Password!29", IdempotencyKey: "change-a-password"})
	if err != nil {
		t.Fatal(err)
	}
	assertFederatedLoginResolvesLinkedWorkspace(t, mounted, primarySession.AccessToken, session.AccessToken)
	unscopedLogin := httptest.NewRecorder()
	unscopedRequest := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"login":"`+b.InitialAdminLoginID+`","password":"Workspace-B-Test-Password!29"}`))
	mounted.ServeHTTP(unscopedLogin, unscopedRequest)
	if unscopedLogin.Code != http.StatusOK || !strings.Contains(unscopedLogin.Body.String(), `"workspace_id":"workspace-b"`) {
		t.Fatalf("unscoped login did not resolve its unique Workspace: status=%d body=%s", unscopedLogin.Code, unscopedLogin.Body.String())
	}
	cookies := unscopedLogin.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" {
		t.Fatalf("unscoped login refresh cookie=%#v", cookies)
	}
	unscopedRefreshRequest := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(`{}`))
	unscopedRefreshRequest.AddCookie(cookies[0])
	unscopedRefresh := httptest.NewRecorder()
	mounted.ServeHTTP(unscopedRefresh, unscopedRefreshRequest)
	if unscopedRefresh.Code != http.StatusOK || !strings.Contains(unscopedRefresh.Body.String(), `"workspace_id":"workspace-b"`) {
		t.Fatalf("unscoped refresh did not recover its Workspace: status=%d body=%s", unscopedRefresh.Code, unscopedRefresh.Body.String())
	}
	for _, header := range []string{"", "workspace-primary"} {
		request := httptest.NewRequest(http.MethodGet, "/identity/users", nil)
		request.Header.Set("Authorization", "Bearer "+session.AccessToken)
		request.Header.Set("X-Workspace-ID", header)
		response := httptest.NewRecorder()
		mounted.ServeHTTP(response, request)
		if header != "" {
			if response.Code != http.StatusForbidden {
				t.Fatalf("conflicting workspace status %d", response.Code)
			}
			continue
		}
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), credential.LoginID) || strings.Contains(response.Body.String(), a.InitialAdminLoginID) {
			t.Fatalf("management request did not remain within B: status %d", response.Code)
		}
	}
	delete(resolver, "public-b")
	delete(resolver, "workspace-b")
	if _, err := binding.Authentication().RefreshSession(t.Context(), identitysdk.RefreshRequest{WorkspaceID: "workspace-b", RefreshToken: session.RefreshToken}); err == nil {
		t.Fatal("inactive refresh accepted")
	}
	if _, err := binding.Authentication().CurrentSession(t.Context(), identitysdk.CurrentSessionRequest{AccessToken: session.AccessToken}); err == nil {
		t.Fatal("inactive token accepted")
	}
}

func assertFederatedLoginResolvesLinkedWorkspace(t *testing.T, mounted http.Handler, primaryAccessToken, linkedAccessToken string) {
	t.Helper()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			var payload struct {
				CodeVerifier string `json:"code_verifier"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || strings.TrimSpace(payload.CodeVerifier) == "" {
				http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"code":0,"access_token":"feishu-access"}`))
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer feishu-access" {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"union_id":"feishu-user-b","name":"Workspace B User"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	setupBody := `{"type":"oidc","client_id":"feishu-app","client_secret":"feishu-secret","redirect_url":"http://localhost/auth/providers/feishu/callback","token_url":"` + provider.URL + `/token","userinfo_url":"` + provider.URL + `/userinfo","scope":"openid","auto_create_users":false}`
	setupRequest := httptest.NewRequest(http.MethodPut, "/auth/providers/feishu/setup", strings.NewReader(setupBody))
	setupRequest.Header.Set("Content-Type", "application/json")
	setupRequest.Header.Set("Authorization", "Bearer "+primaryAccessToken)
	setupResponse := httptest.NewRecorder()
	mounted.ServeHTTP(setupResponse, setupRequest)
	if setupResponse.Code != http.StatusOK {
		t.Fatalf("configure Feishu provider status=%d body=%s", setupResponse.Code, setupResponse.Body.String())
	}

	const returnURL = "http://localhost:3100/auth/callback"
	linkRequest := httptest.NewRequest(http.MethodPost, "/auth/external-accounts/feishu/link/start", strings.NewReader(`{"return_url":"`+returnURL+`"}`))
	linkRequest.Header.Set("Content-Type", "application/json")
	linkRequest.Header.Set("Authorization", "Bearer "+linkedAccessToken)
	linkRequest.Header.Set("X-Workspace-ID", "workspace-b")
	linkResponse := httptest.NewRecorder()
	mounted.ServeHTTP(linkResponse, linkRequest)
	var linkStarted struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(linkResponse.Body.Bytes(), &linkStarted); err != nil || linkResponse.Code != http.StatusOK || linkStarted.State == "" {
		t.Fatalf("link Workspace B Feishu account status=%d body=%s err=%v", linkResponse.Code, linkResponse.Body.String(), err)
	}
	linkCallback := httptest.NewRecorder()
	mounted.ServeHTTP(linkCallback, httptest.NewRequest(http.MethodGet, "/auth/providers/feishu/callback?code=provider-code&state="+url.QueryEscape(linkStarted.State), nil))
	if linkCallback.Code != http.StatusSeeOther {
		t.Fatalf("link callback status=%d body=%s", linkCallback.Code, linkCallback.Body.String())
	}

	startRequest := httptest.NewRequest(http.MethodPost, "/auth/providers/feishu/start", strings.NewReader(`{"return_url":"`+returnURL+`"}`))
	startRequest.Header.Set("Content-Type", "application/json")
	startResponse := httptest.NewRecorder()
	mounted.ServeHTTP(startResponse, startRequest)
	var started struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(startResponse.Body.Bytes(), &started); err != nil || startResponse.Code != http.StatusOK || started.State == "" {
		t.Fatalf("unscoped Feishu start status=%d body=%s err=%v", startResponse.Code, startResponse.Body.String(), err)
	}

	callbackResponse := httptest.NewRecorder()
	mounted.ServeHTTP(callbackResponse, httptest.NewRequest(http.MethodGet, "/auth/providers/feishu/callback?code=provider-code&state="+url.QueryEscape(started.State), nil))
	if callbackResponse.Code != http.StatusSeeOther {
		t.Fatalf("Feishu callback status=%d body=%s", callbackResponse.Code, callbackResponse.Body.String())
	}
	redirect, err := url.Parse(callbackResponse.Header().Get("Location"))
	if err != nil || redirect.Query().Get("code") == "" {
		t.Fatalf("Feishu callback redirect=%q err=%v", callbackResponse.Header().Get("Location"), err)
	}

	exchangeRequest := httptest.NewRequest(http.MethodPost, "/auth/code/exchange", strings.NewReader(`{"code":"`+redirect.Query().Get("code")+`","return_url":"`+returnURL+`"}`))
	exchangeRequest.Header.Set("Content-Type", "application/json")
	exchangeResponse := httptest.NewRecorder()
	mounted.ServeHTTP(exchangeResponse, exchangeRequest)
	if exchangeResponse.Code != http.StatusOK || !strings.Contains(exchangeResponse.Body.String(), `"workspace_id":"workspace-b"`) {
		t.Fatalf("unscoped authorization-code exchange status=%d body=%s", exchangeResponse.Code, exchangeResponse.Body.String())
	}
}
