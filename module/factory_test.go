package module_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	dataexchangemodulehost "github.com/domainry/domainry-data-exchange-sdk/modulehost"
	actioncontract "github.com/domainry/domainry-foundation/action"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitycontracttest "github.com/domainry/domainry-identity-sdk/contracttest"
	identityhttpapi "github.com/domainry/domainry-identity-sdk/httpapi"
	identitymodule "github.com/domainry/domainry-identity/module"
)

type testClock struct{ now time.Time }

func (clock testClock) Now() time.Time { return clock.now }

func permissionReconcileRequest(t *testing.T, application identitysdk.ApplicationRef, sourceOwner, previousSnapshotHash string, definitions []identitysdk.PermissionDefinition) identitysdk.PermissionReconcileRequest {
	t.Helper()
	request, err := identitysdk.NewPermissionReconcileRequest(application, sourceOwner, previousSnapshotHash, definitions)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

type testEmbeddedMigrationCall struct {
	owner   string
	version uint
	name    string
}

type testEmbeddedMigrationRegistrar struct {
	calls []testEmbeddedMigrationCall
}

func (registrar *testEmbeddedMigrationRegistrar) ApplyOwnedMigration(ctx context.Context, owner string, version uint, name, _ string, apply func(context.Context) error) error {
	registrar.calls = append(registrar.calls, testEmbeddedMigrationCall{owner: owner, version: version, name: name})
	return apply(ctx)
}

func TestFactoryOpensDirectSDKBinding(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve module test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), ".."))
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_DRIVER", "sqlite")
	moduleDBPath := filepath.Join(t.TempDir(), "identity.db")
	t.Setenv("APP_DB_PATH", filepath.Join(t.TempDir(), "runtime-must-not-be-used.db"))
	t.Setenv("TEMPLATE_MANIFEST", filepath.Join(projectRoot, "domainry.template.json"))
	t.Setenv("AUTH_AUDIENCE", "must-not-win-over-host-application")
	now := time.Now().UTC().Truncate(time.Second)
	application := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime"}
	factory := identitymodule.NewFactory(identitymodule.Options{IdentityVersion: "test", DatabaseDriver: "sqlite", DatabasePath: moduleDBPath, Clock: testClock{now: now}})
	binding, err := factory.Open(t.Context(), application)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Descriptor().Mode != identitysdk.DeploymentModeModule {
		t.Fatalf("mode = %q", binding.Descriptor().Mode)
	}
	if binding.Descriptor().Audience != "orders-runtime" {
		t.Fatalf("module audience=%q want host application audience", binding.Descriptor().Audience)
	}
	if _, advertised := binding.(identitysdk.ApplicationServiceBinding); advertised {
		t.Fatal("embedded Identity binding advertised application service token exchange")
	}
	verification, ok := binding.(identitysdk.ApplicationServiceVerificationBinding)
	if !ok || verification.ApplicationServiceVerifier() == nil {
		t.Fatal("embedded Identity binding does not expose service token verification")
	}
	providerSource, ok := binding.(interface {
		IdentityDataExchangeProviders() (string, dataexchangemodulehost.ImportProvider, dataexchangemodulehost.ExportProvider)
	})
	if !ok {
		t.Fatal("module Binding does not expose its Data Exchange providers")
	}
	providerKey, importProvider, exportProvider := providerSource.IdentityDataExchangeProviders()
	if providerKey != identitymodule.IdentityPortabilityProviderKey || importProvider == nil || exportProvider == nil {
		t.Fatalf("Data Exchange providers key=%q import=%T export=%T", providerKey, importProvider, exportProvider)
	}
	if _, ok := importProvider.(dataexchangemodulehost.ImportArtifactProvider); !ok {
		t.Fatalf("Identity import provider %T does not support atomic artifacts", importProvider)
	}
	if _, ok := exportProvider.(dataexchangemodulehost.ExportArtifactProvider); !ok {
		t.Fatalf("Identity export provider %T does not support canonical artifacts", exportProvider)
	}
	httpProvider, ok := binding.(identityhttpapi.Provider)
	if !ok {
		t.Fatal("module Binding does not expose its HTTP Surfaces")
	}
	surfaces := httpProvider.HTTPSurfaces()
	if len(surfaces) != 2 {
		t.Fatalf("HTTP surface count=%d", len(surfaces))
	}
	foundUsers, foundLogin := false, false
	for _, surface := range surfaces {
		if surface == nil || surface.Handler() == nil || surface.ContractVersion() != identityhttpapi.ContractVersion {
			t.Fatalf("invalid module HTTP Surface %#v", surface)
		}
		for _, route := range surface.Routes() {
			if route.Pattern() == "GET /identity/users" {
				foundUsers = true
			}
			if route.Pattern() == "POST /auth/login" {
				foundLogin = true
			}
			if route.Pattern() == "GET /health" {
				t.Fatalf("standalone-only route leaked into module HTTP Surface: %q", route.Pattern())
			}
		}
	}
	if !foundUsers || !foundLogin {
		t.Fatalf("module surfaces users=%v login=%v", foundUsers, foundLogin)
	}
	mounted := http.NewServeMux()
	mountedPatterns := map[string]string{}
	for _, surface := range surfaces {
		for _, route := range surface.Routes() {
			pattern := route.Pattern()
			if owner, duplicate := mountedPatterns[pattern]; duplicate {
				t.Fatalf("module route %q is duplicated by %q and %q", pattern, owner, surface.Name())
			}
			mountedPatterns[pattern] = surface.Name()
			mounted.Handle(pattern, surface.Handler())
		}
	}
	for pattern, wantExposure := range map[string]identityhttpapi.Exposure{
		"GET /.well-known/jwks.json":                            identityhttpapi.ExposurePublic,
		"GET /.well-known/openid-configuration":                 identityhttpapi.ExposurePublic,
		"POST /auth/login":                                      identityhttpapi.ExposurePublic,
		"POST /auth/guest":                                      identityhttpapi.ExposurePublic,
		"POST /auth/providers/{provider}/exchange":              identityhttpapi.ExposurePublic,
		"GET /auth/providers/{provider}/setup-check":            identityhttpapi.ExposureTenantAdmin,
		"PUT /auth/providers/{provider}/setup":                  identityhttpapi.ExposureTenantAdmin,
		"GET /auth/external-accounts":                           identityhttpapi.ExposurePublic,
		"POST /auth/external-accounts/{provider}/bind":          identityhttpapi.ExposurePublic,
		"DELETE /auth/external-accounts/{provider}/{accountID}": identityhttpapi.ExposurePublic,
		"GET /auth/me":                                          identityhttpapi.ExposurePublic,
		"PATCH /auth/me":                                        identityhttpapi.ExposurePublic,
		"GET /auth/role-options":                                identityhttpapi.ExposurePublic,
		"GET /auth/role-requests":                               identityhttpapi.ExposurePublic,
		"POST /auth/role-requests":                              identityhttpapi.ExposurePublic,
		"POST /auth/reset-password":                             identityhttpapi.ExposureTenantAdmin,
	} {
		owner, ok := mountedPatterns[pattern]
		if !ok {
			t.Fatalf("module route %q is not exported", pattern)
		}
		foundExposure := false
		for _, surface := range surfaces {
			if surface.Name() != owner {
				continue
			}
			for _, route := range surface.Routes() {
				if route.Pattern() == pattern {
					for _, exposure := range route.Action.Exposures {
						if exposure == wantExposure {
							foundExposure = true
						}
					}
				}
			}
		}
		if !foundExposure {
			t.Fatalf("module route %q does not have exposure %q", pattern, wantExposure)
		}
	}
	if _, err := binding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{
		Application: application, RedirectURLs: []string{"http://localhost:3100/auth/callback"},
	}); err != nil {
		t.Fatalf("register project application: %v", err)
	}
	permissionDefinitions := []identitysdk.PermissionDefinition{{PermissionKey: "customer.read", ResourceKey: "customer", ActionKey: "read", Label: "Read customers", Category: "Orders", SourceKind: "object_action"}}
	receipt, err := binding.Permissions().Reconcile(t.Context(), permissionReconcileRequest(t, application, "application:orders-runtime", "", permissionDefinitions))
	if err != nil || receipt.SourceOwner != "application:orders-runtime" {
		t.Fatalf("permission receipt=%#v err=%v", receipt, err)
	}
	rolePublisher, ok := binding.(identitysdk.ProjectRoleCatalogPublisher)
	if !ok {
		t.Fatal("module Binding does not expose project role publication")
	}
	roleReceipt, err := rolePublisher.PublishProjectRoles(t.Context(), identitysdk.ProjectRoleCatalog{
		Application: application,
		Roles: []identitysdk.ProjectRoleDefinition{{
			Key: "project_viewer", Name: "Project Viewer", Permissions: []string{"customer.read"}, RecordScope: "all_records",
			Audience: "any", AssignmentMode: "manual", RiskLevel: "normal", SchemaHash: strings.Repeat("a", 64),
			DataPermissions: json.RawMessage(`[{"object_key":"customer","scope":"all_records","read":true,"write":false}]`),
		}},
	})
	if err != nil || roleReceipt.Published != 1 || len(roleReceipt.SHA256) != 64 {
		t.Fatalf("project role receipt=%#v err=%v", roleReceipt, err)
	}
	repeatedRoleReceipt, err := rolePublisher.PublishProjectRoles(t.Context(), identitysdk.ProjectRoleCatalog{
		Application: application,
		Roles: []identitysdk.ProjectRoleDefinition{{
			Key: "project_viewer", Name: "Project Viewer", Permissions: []string{"customer.read"}, RecordScope: "all_records",
			Audience: "any", AssignmentMode: "manual", RiskLevel: "normal", SchemaHash: strings.Repeat("a", 64),
			DataPermissions: json.RawMessage(`[{"object_key":"customer","scope":"all_records","read":true,"write":false}]`),
		}},
	})
	if err != nil || repeatedRoleReceipt != roleReceipt {
		t.Fatalf("idempotent project role receipt=%#v want=%#v err=%v", repeatedRoleReceipt, roleReceipt, err)
	}
	if _, err := rolePublisher.PublishProjectRoles(t.Context(), identitysdk.ProjectRoleCatalog{Application: identitysdk.ApplicationRef{WorkspaceID: "other", ApplicationKey: application.ApplicationKey}}); err == nil {
		t.Fatal("cross-workspace project role publication accepted")
	}
	roles, err := binding.Directory().ListRoles(t.Context(), identitysdk.DirectoryQuery{Application: identitysdk.ApplicationScope{WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey}})
	if err != nil {
		t.Fatal(err)
	}
	foundProjectRole := false
	for _, role := range roles {
		foundProjectRole = foundProjectRole || role.Key == "project_viewer"
	}
	if !foundProjectRole {
		t.Fatalf("project role missing from directory: %#v", roles)
	}

	unauthenticatedSetup := httptest.NewRecorder()
	unauthenticatedSetupRequest := httptest.NewRequest(http.MethodPut, "/auth/providers/wechat_mini_program/setup", strings.NewReader(`{}`))
	unauthenticatedSetupRequest.Header.Set("Content-Type", "application/json")
	mounted.ServeHTTP(unauthenticatedSetup, unauthenticatedSetupRequest)
	if unauthenticatedSetup.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated provider setup status=%d body=%s", unauthenticatedSetup.Code, unauthenticatedSetup.Body.String())
	}

	adminSession, err := binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{
		WorkspaceID: "workspace-primary", Login: "admin@example.com", Password: "Domainry@2026",
	})
	if err != nil || adminSession.AccessToken == "" {
		t.Fatalf("workspace admin login session=%#v err=%v", adminSession, err)
	}
	embeddedRegistry := actioncontract.NewRegistry()
	if err := embeddedRegistry.Register(actioncontract.ActionDefinition{
		Key: "customer.read", Owner: "application:orders-runtime", SourceKind: "object_action",
		CapabilityKey: "customer", CapabilityLabel: "Customer", OperationKey: "read", OperationLabel: "Read customers", Label: "Read customers",
		Exposures:     []actioncontract.Exposure{actioncontract.ExposureTenantAdmin},
		Authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationExactRolePermission},
		NonHTTP:       []actioncontract.NonHTTPBinding{{Kind: "rpc", InvocationKey: "customer.read"}},
		Permission: &actioncontract.PermissionDefinition{
			Key: "customer.read", Owner: "application:orders-runtime", ResourceKey: "customer", ActionKey: "read",
			Label: "Read customers", Category: "Orders", LifecycleStatus: actioncontract.LifecycleActive,
		},
		EffectClass: actioncontract.EffectRead, RiskLevel: actioncontract.RiskLow, IdempotencyDecision: "not_applicable", AuditClass: "customer_read", LifecycleStatus: actioncontract.LifecycleActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := embeddedRegistry.Freeze(); err != nil {
		t.Fatal(err)
	}
	usageBinder, ok := binding.(identitysdk.PermissionUsageProviderBinder)
	if !ok {
		t.Fatal("module Binding does not accept the host Action usage provider")
	}
	if err := usageBinder.BindPermissionUsageProvider(embeddedRegistry); err != nil {
		t.Fatal(err)
	}
	permissionList := httptest.NewRecorder()
	permissionListRequest := httptest.NewRequest(http.MethodGet, "/identity/permissions", nil)
	permissionListRequest.Header.Set("Authorization", "Bearer "+adminSession.AccessToken)
	mounted.ServeHTTP(permissionList, permissionListRequest)
	if permissionList.Code != http.StatusOK {
		t.Fatalf("embedded permission list status=%d body=%s", permissionList.Code, permissionList.Body.String())
	}
	var projectedPermissions []struct {
		Key               string `json:"key"`
		ActionUsageStatus string `json:"action_usage_status"`
		ActionUsages      []struct {
			ActionKey string `json:"action_key"`
		} `json:"action_usages"`
	}
	if err := json.Unmarshal(permissionList.Body.Bytes(), &projectedPermissions); err != nil {
		t.Fatal(err)
	}
	foundCustomerUsage := false
	for _, permission := range projectedPermissions {
		if permission.Key == "customer.read" {
			foundCustomerUsage = permission.ActionUsageStatus == "available" && len(permission.ActionUsages) == 1 && permission.ActionUsages[0].ActionKey == "customer.read"
		}
	}
	if !foundCustomerUsage {
		t.Fatalf("embedded host registry usage was not projected: %#v", projectedPermissions)
	}
	reset := httptest.NewRecorder()
	resetRequest := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(`{"user_id":"admin","new_password":"Domainry@2026","must_change_password":false}`))
	resetRequest.Header.Set("Content-Type", "application/json")
	resetRequest.Header.Set("Authorization", "Bearer "+adminSession.AccessToken)
	resetRequest.Header.Set("Idempotency-Key", "reset-missing-user")
	mounted.ServeHTTP(reset, resetRequest)
	if reset.Code != http.StatusOK {
		t.Fatalf("mounted tenant-admin reset-password status=%d body=%s", reset.Code, reset.Body.String())
	}
	for _, resourceType := range []string{"role", "permission"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/tenant-admin/metadata/definitions/"+resourceType, nil)
		request.Header.Set("Authorization", "Bearer "+adminSession.AccessToken)
		mounted.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("retired Identity metadata route %s status=%d body=%s", resourceType, response.Code, response.Body.String())
		}
	}
	wechat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"openid":"wechat-subject"}`))
	}))
	t.Cleanup(wechat.Close)
	adminSetup := httptest.NewRecorder()
	adminSetupBody := fmt.Sprintf(`{"type":"code_exchange","adapter":"wechat_mini_program","client_id":"app-id","client_secret":"app-secret","token_url":%q}`, wechat.URL)
	adminSetupRequest := httptest.NewRequest(http.MethodPut, "/auth/providers/wechat_mini_program/setup", strings.NewReader(adminSetupBody))
	adminSetupRequest.Header.Set("Content-Type", "application/json")
	adminSetupRequest.Header.Set("Authorization", "Bearer "+adminSession.AccessToken)
	mounted.ServeHTTP(adminSetup, adminSetupRequest)
	if adminSetup.Code != http.StatusOK {
		t.Fatalf("workspace admin provider setup did not reach handler: status=%d body=%s", adminSetup.Code, adminSetup.Body.String())
	}
	setupCheck := httptest.NewRecorder()
	mounted.ServeHTTP(setupCheck, httptest.NewRequest(http.MethodGet, "/auth/providers/wechat_mini_program/setup-check", nil))
	if setupCheck.Code != http.StatusOK {
		t.Fatalf("provider setup-check did not reach handler: status=%d body=%s", setupCheck.Code, setupCheck.Body.String())
	}

	unauthenticatedBind := httptest.NewRecorder()
	unauthenticatedBindRequest := httptest.NewRequest(http.MethodPost, "/auth/external-accounts/wechat_mini_program/bind", strings.NewReader(`{"subject":"wechat-subject"}`))
	unauthenticatedBindRequest.Header.Set("Content-Type", "application/json")
	mounted.ServeHTTP(unauthenticatedBind, unauthenticatedBindRequest)
	if unauthenticatedBind.Code != http.StatusForbidden && unauthenticatedBind.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated external-account bind status=%d body=%s", unauthenticatedBind.Code, unauthenticatedBind.Body.String())
	}

	bind := httptest.NewRecorder()
	bindRequest := httptest.NewRequest(http.MethodPost, "/auth/external-accounts/wechat_mini_program/bind", strings.NewReader(`{"subject":"wechat-subject"}`))
	bindRequest.Header.Set("Content-Type", "application/json")
	bindRequest.Header.Set("Authorization", "Bearer "+adminSession.AccessToken)
	mounted.ServeHTTP(bind, bindRequest)
	if bind.Code != http.StatusCreated {
		t.Fatalf("external-account bind status=%d body=%s", bind.Code, bind.Body.String())
	}
	var boundAccount struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(bind.Body.Bytes(), &boundAccount); err != nil || boundAccount.ID == "" {
		t.Fatalf("decode bound account=%#v err=%v body=%s", boundAccount, err, bind.Body.String())
	}

	list := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/auth/external-accounts", nil)
	listRequest.Header.Set("Authorization", "Bearer "+adminSession.AccessToken)
	mounted.ServeHTTP(list, listRequest)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "wechat-subject") {
		t.Fatalf("external-account list status=%d body=%s", list.Code, list.Body.String())
	}

	publicExchange := httptest.NewRecorder()
	publicExchangeRequest := httptest.NewRequest(http.MethodPost, "/auth/providers/wechat_mini_program/exchange", strings.NewReader(`{"workspace_id":"workspace-primary","application_key":"orders-runtime","code":"wx-code"}`))
	publicExchangeRequest.Header.Set("Content-Type", "application/json")
	mounted.ServeHTTP(publicExchange, publicExchangeRequest)
	if publicExchange.Code != http.StatusOK {
		t.Fatalf("bound public provider exchange status=%d body=%s", publicExchange.Code, publicExchange.Body.String())
	}

	unbind := httptest.NewRecorder()
	unbindRequest := httptest.NewRequest(http.MethodDelete, "/auth/external-accounts/wechat_mini_program/"+boundAccount.ID, nil)
	unbindRequest.Header.Set("Authorization", "Bearer "+adminSession.AccessToken)
	mounted.ServeHTTP(unbind, unbindRequest)
	if unbind.Code != http.StatusOK {
		t.Fatalf("external-account unbind status=%d body=%s", unbind.Code, unbind.Body.String())
	}
	managementSurface := surfaces[1]
	response := httptest.NewRecorder()
	managementSurface.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/identity/users", nil))
	if response.Code == http.StatusNotFound {
		t.Fatal("module management route list points at an unregistered Handler route")
	}
	repeatedReceipt, err := binding.Permissions().Reconcile(t.Context(), permissionReconcileRequest(t, application, "application:orders-runtime", receipt.SnapshotHash, permissionDefinitions))
	if err != nil || repeatedReceipt.SnapshotHash != receipt.SnapshotHash || repeatedReceipt.Unchanged != 1 {
		t.Fatalf("idempotent permission reconcile receipt=%#v want hash=%q err=%v", repeatedReceipt, receipt.SnapshotHash, err)
	}
	changedDefinitions := append([]identitysdk.PermissionDefinition(nil), permissionDefinitions...)
	changedDefinitions[0].Label = "Read current customers"
	staleRequest := permissionReconcileRequest(t, application, "application:orders-runtime", strings.Repeat("0", 64), changedDefinitions)
	if _, err := binding.Permissions().Reconcile(t.Context(), staleRequest); err == nil {
		t.Fatal("embedded binding accepted a stale permission snapshot")
	} else {
		var sdkError *identitysdk.Error
		if !errors.As(err, &sdkError) || sdkError.StatusCode != http.StatusConflict || sdkError.Code != "identity.permission_snapshot_stale" {
			t.Fatalf("embedded stale snapshot error=%#v", err)
		}
	}
	ownerConflictRequest := permissionReconcileRequest(t, application, "application:other-runtime", "", permissionDefinitions)
	if _, err := binding.Permissions().Reconcile(t.Context(), ownerConflictRequest); err == nil {
		t.Fatal("embedded binding accepted a permission owner conflict")
	} else {
		var sdkError *identitysdk.Error
		if !errors.As(err, &sdkError) || sdkError.StatusCode != http.StatusConflict || sdkError.Code != "identity.permission_owner_conflict" {
			t.Fatalf("embedded permission owner conflict error=%#v", err)
		}
	}
	moduleDB, err := sql.Open("sqlite", moduleDBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = moduleDB.Close() })
	var applicationCount, permissionCount int
	if err := moduleDB.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_applications WHERE workspace_id = ? AND application_key = ?`, "workspace-primary", "orders-runtime").Scan(&applicationCount); err != nil || applicationCount != 1 {
		t.Fatalf("application registration count=%d err=%v", applicationCount, err)
	}
	if err := moduleDB.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_permissions WHERE workspace_id = ? AND permission_key = ? AND source_owner = ?`, "workspace-primary", "customer.read", "application:orders-runtime").Scan(&permissionCount); err != nil || permissionCount != 1 {
		t.Fatalf("permission definition count=%d err=%v", permissionCount, err)
	}
	otherWorkspaceApplication := application
	otherWorkspaceApplication.WorkspaceID = "workspace-2"
	if _, err := binding.Permissions().Reconcile(t.Context(), permissionReconcileRequest(t, otherWorkspaceApplication, "application:orders-runtime", "", nil)); err == nil {
		t.Fatal("application-scoped module binding reconciled another workspace")
	}
	identitycontracttest.Run(t, identitycontracttest.Fixture{
		Binding: binding, WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime", Login: "admin@example.com", Password: "Domainry@2026",
		Resource: "identity.users", Action: "list", DataAction: identitysdk.DataActionRead,
	})
	if err := binding.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	reopened, err := factory.Open(t.Context(), application)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close(t.Context())
	reopenedReceipt, err := reopened.Permissions().Reconcile(t.Context(), permissionReconcileRequest(t, application, "application:orders-runtime", receipt.SnapshotHash, permissionDefinitions))
	if err != nil || reopenedReceipt.SnapshotHash != receipt.SnapshotHash || reopenedReceipt.Unchanged != 1 {
		t.Fatalf("reopened permission receipt=%#v want hash=%q err=%v", reopenedReceipt, receipt.SnapshotHash, err)
	}
}

func TestFactoryRejectsMissingApplication(t *testing.T) {
	if _, err := identitymodule.NewFactory(identitymodule.Options{}).Open(t.Context(), identitysdk.ApplicationRef{}); err == nil {
		t.Fatal("module factory accepted a missing application scope")
	}
}

func TestFactoryRejectsUnavailableContextBeforeOpeningInfrastructure(t *testing.T) {
	factory := identitymodule.NewFactory(identitymodule.Options{})
	application := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime"}
	if _, err := factory.Open(nil, application); err == nil {
		t.Fatal("module factory accepted a nil context")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := factory.Open(ctx, application); err == nil {
		t.Fatal("module factory accepted a cancelled context")
	}
}

func TestOptionsFromEnvironmentUsesModuleOwnedDatabaseNamespace(t *testing.T) {
	t.Setenv("DATABASE_DRIVER", "postgres")
	t.Setenv("DATABASE_DSN", "runtime-dsn")
	t.Setenv("APP_DB_PATH", "runtime.db")
	t.Setenv("IDENTITY_MODULE_DATABASE_DRIVER", "sqlite")
	t.Setenv("IDENTITY_MODULE_DATABASE_DSN", "identity-dsn")
	t.Setenv("IDENTITY_MODULE_DATABASE_MIGRATION_DSN", "identity-migration-dsn")
	t.Setenv("IDENTITY_MODULE_DATABASE_SCHEMA", "identity")
	t.Setenv("IDENTITY_MODULE_DB_PATH", "identity.db")

	options := identitymodule.OptionsFromEnvironment()
	if options.DatabaseDriver != "sqlite" || options.DatabaseDSN != "identity-dsn" || options.DatabaseMigrationDSN != "identity-migration-dsn" || options.DatabaseSchema != "identity" || options.DatabasePath != "identity.db" {
		t.Fatalf("module database options=%#v", options)
	}
}

func TestFactoryBorrowsProjectPoolWithoutClosingOrColliding(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "project.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(t.Context(), `CREATE TABLE metadata_catalog (owner TEXT NOT NULL); INSERT INTO metadata_catalog (owner) VALUES ('runtime'); CREATE TABLE runtime_audit_events (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL); INSERT INTO runtime_audit_events (id, workspace_id) VALUES ('runtime-event', 'workspace-primary')`); err != nil {
		t.Fatal(err)
	}
	factory := identitymodule.NewFactory(identitymodule.Options{DatabaseDriver: "sqlite", DatabasePath: dbPath})
	registrar := &testEmbeddedMigrationRegistrar{}
	binding, err := factory.OpenWithDatabase(t.Context(), identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "crm"}, identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: dbPath, Migrations: registrar})
	if err != nil {
		t.Fatal(err)
	}
	if err := binding.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if stats := db.Stats(); stats.MaxOpenConnections != 3 {
		t.Fatalf("Identity Module reinitialized host pool: max open=%d", stats.MaxOpenConnections)
	}
	var owner string
	if err := db.QueryRowContext(t.Context(), `SELECT owner FROM metadata_catalog`).Scan(&owner); err != nil || owner != "runtime" {
		t.Fatalf("runtime table changed or pool closed: owner=%q err=%v", owner, err)
	}
	var runtimeAuditEvents int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM runtime_audit_events WHERE workspace_id = 'workspace-primary'`).Scan(&runtimeAuditEvents); err != nil || runtimeAuditEvents != 1 {
		t.Fatalf("Runtime-owned workspace table changed: count=%d err=%v", runtimeAuditEvents, err)
	}
	var identityUsers int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_users'`).Scan(&identityUsers); err != nil || identityUsers != 1 {
		t.Fatalf("borrowed Identity users table=%d err=%v", identityUsers, err)
	}
	var prefixedTables int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'domainry_identity_%'`).Scan(&prefixedTables); err != nil || prefixedTables != 0 {
		t.Fatalf("borrowed Identity prefixed tables=%d err=%v", prefixedTables, err)
	}
	var migrationLedgers int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%schema_migrations'`).Scan(&migrationLedgers); err != nil || migrationLedgers != 1 {
		t.Fatalf("migration ledgers=%d err=%v", migrationLedgers, err)
	}
	if len(registrar.calls) != 1 || registrar.calls[0] != (testEmbeddedMigrationCall{owner: "identity", version: 2, name: "identity_authorization_permissions"}) {
		t.Fatalf("host migration calls=%#v", registrar.calls)
	}
}

func TestFactoryRejectsBorrowedDatabaseWithoutHostMigrationRegistrar(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "project.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = identitymodule.NewFactory(identitymodule.Options{DatabaseDriver: "sqlite"}).OpenWithDatabase(t.Context(), identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime"}, identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite"})
	var sdkErr *identitysdk.Error
	if !errors.As(err, &sdkErr) || sdkErr.Code != "identity.module_migration_registrar_required" {
		t.Fatalf("missing registrar error=%v", err)
	}
}
