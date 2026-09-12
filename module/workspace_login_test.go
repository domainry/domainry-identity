package module_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	initialCatalog.Roles[0].Permissions = []identitysdk.ProjectRolePermission{{PermissionKey: "identity.users.list", DataScope: "all"}}
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
	resolver := testWorkspaceResolver{"public-a": "workspace-primary", "workspace-primary": "workspace-primary", "public-b": "workspace-b", "workspace-b": "workspace-b"}
	binding, err := identitymodule.NewFactory(identitymodule.Options{IdentityVersion: "test", DatabaseDriver: "sqlite"}).OpenWithDatabase(t.Context(), identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime"}, identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", Migrations: &testEmbeddedMigrationRegistrar{}, WorkspaceResolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(context.Background()) })
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
