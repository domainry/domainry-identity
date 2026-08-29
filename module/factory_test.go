package module_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitycontracttest "github.com/domainry/domainry-identity-sdk/contracttest"
	identityhttpapi "github.com/domainry/domainry-identity-sdk/httpapi"
	identitymodule "github.com/domainry/domainry-identity/module"
)

type testClock struct{ now time.Time }

func (clock testClock) Now() time.Time { return clock.now }

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
	application := identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "orders-runtime", RedirectURLs: []string{"http://localhost:3100/auth/callback"}}
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
			if route.Pattern == "GET /identity/users" {
				foundUsers = true
			}
			if route.Pattern == "POST /auth/login" {
				foundLogin = true
			}
			if route.Pattern == "GET /health" {
				t.Fatalf("standalone-only route leaked into module HTTP Surface: %q", route.Pattern)
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
			if owner, duplicate := mountedPatterns[route.Pattern]; duplicate {
				t.Fatalf("module route %q is duplicated by %q and %q", route.Pattern, owner, surface.Name())
			}
			mountedPatterns[route.Pattern] = surface.Name()
			mounted.Handle(route.Pattern, surface.Handler())
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
		"PUT /tenant-admin/change-plans/{planID}":               identityhttpapi.ExposureTenantAdmin,
		"POST /tenant-admin/change-plans/{planID}/review":       identityhttpapi.ExposureTenantAdmin,
		"POST /tenant-admin/change-plans/{planID}/approve":      identityhttpapi.ExposureTenantAdmin,
		"POST /tenant-admin/change-plans/apply":                 identityhttpapi.ExposureTenantAdmin,
		"GET /domain-system-snapshot":                           identityhttpapi.ExposureTenantAdmin,
		"GET /domain-reference-graph":                           identityhttpapi.ExposureTenantAdmin,
		"GET /tenant-admin/metadata/definitions/{resourceType}": identityhttpapi.ExposureTenantAdmin,
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
				if route.Pattern == pattern {
					for _, exposure := range route.Exposures {
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
	catalog := identitysdk.AuthorizationCatalog{
		ContractVersion: identitysdk.CatalogVersionV1,
		Application:     identitysdk.ApplicationRef{ApplicationKey: "orders-runtime", WorkspaceID: "default", RedirectURLs: []string{"http://localhost:3100/auth/callback"}},
		Resources:       []identitysdk.ResourceDefinition{{Key: "customer", Fields: []string{"id"}, SupportedFacts: []string{"id"}}},
		Actions:         []identitysdk.ActionDefinition{{Resource: "customer", Action: "read"}},
	}
	receipt, err := binding.Catalog().Publish(t.Context(), catalog)
	if err != nil || receipt.Revision == "" {
		t.Fatalf("publish receipt=%#v err=%v", receipt, err)
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
		WorkspaceID: "default", Login: "admin@example.com", Password: "Domainry@2026",
	})
	if err != nil || adminSession.AccessToken == "" {
		t.Fatalf("workspace admin login session=%#v err=%v", adminSession, err)
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
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"definitions"`) {
			t.Fatalf("mounted %s definitions status=%d body=%s", resourceType, response.Code, response.Body.String())
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
	publicExchangeRequest := httptest.NewRequest(http.MethodPost, "/auth/providers/wechat_mini_program/exchange", strings.NewReader(`{"workspace_id":"default","application_key":"orders-runtime","code":"wx-code"}`))
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
	if receipt.PublishedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("catalog publication time=%q want=%q", receipt.PublishedAt, now.Format(time.RFC3339Nano))
	}
	repeatedReceipt, err := binding.Catalog().Publish(t.Context(), catalog)
	if err != nil || repeatedReceipt != receipt {
		t.Fatalf("idempotent catalog publish receipt=%#v want=%#v err=%v", repeatedReceipt, receipt, err)
	}
	changedCatalog := catalog
	changedCatalog.Resources = append([]identitysdk.ResourceDefinition(nil), catalog.Resources...)
	changedCatalog.Resources[0].Fields = []string{"id", "name"}
	changedReceipt, err := binding.Catalog().Publish(t.Context(), changedCatalog)
	if err != nil || changedReceipt.Revision == receipt.Revision {
		t.Fatalf("changed catalog receipt=%#v original=%#v err=%v", changedReceipt, receipt, err)
	}
	restoredReceipt, err := binding.Catalog().Publish(t.Context(), catalog)
	if err != nil || restoredReceipt != receipt {
		t.Fatalf("restored immutable catalog receipt=%#v want=%#v err=%v", restoredReceipt, receipt, err)
	}
	moduleDB, err := sql.Open("sqlite", moduleDBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = moduleDB.Close() })
	var revisionCount int
	if err := moduleDB.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM identity_authorization_catalog_revisions WHERE workspace_id = ? AND application_key = ?`, "default", "orders-runtime").Scan(&revisionCount); err != nil || revisionCount != 2 {
		t.Fatalf("catalog revision history count=%d err=%v", revisionCount, err)
	}
	otherWorkspaceCatalog := catalog
	otherWorkspaceCatalog.Application.WorkspaceID = "workspace-2"
	if _, err := binding.Catalog().Publish(t.Context(), otherWorkspaceCatalog); err == nil {
		t.Fatal("application-scoped module binding published another workspace catalog")
	}
	firstWorkspaceReceipt, err := binding.Catalog().CurrentRevision(t.Context(), catalog.Application)
	if err != nil || firstWorkspaceReceipt.Revision != receipt.Revision {
		t.Fatalf("first workspace receipt=%#v want=%#v err=%v", firstWorkspaceReceipt, receipt, err)
	}
	identitycontracttest.Run(t, identitycontracttest.Fixture{
		Binding: binding, WorkspaceID: "default", ApplicationKey: "orders-runtime", Login: "admin@example.com", Password: "Domainry@2026",
		Resource: "customer", Action: "read", CatalogRevision: receipt.Revision,
	})
	if err := binding.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	reopened, err := factory.Open(t.Context(), application)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close(t.Context())
	persisted, err := reopened.Catalog().CurrentRevision(t.Context(), catalog.Application)
	if err != nil || persisted.Revision != receipt.Revision || persisted.SHA256 != receipt.SHA256 {
		t.Fatalf("persisted receipt=%#v want=%#v err=%v", persisted, receipt, err)
	}
	if _, err := reopened.Catalog().CurrentRevision(t.Context(), otherWorkspaceCatalog.Application); err == nil {
		t.Fatal("reopened application-scoped binding read another workspace catalog")
	}
}

func TestFactoryRejectsMissingApplication(t *testing.T) {
	if _, err := identitymodule.NewFactory(identitymodule.Options{}).Open(t.Context(), identitysdk.ApplicationRef{}); err == nil {
		t.Fatal("module factory accepted a missing application scope")
	}
}

func TestFactoryRejectsUnavailableContextBeforeOpeningInfrastructure(t *testing.T) {
	factory := identitymodule.NewFactory(identitymodule.Options{})
	application := identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "orders-runtime"}
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
	if _, err := db.ExecContext(t.Context(), `CREATE TABLE metadata_catalog (owner TEXT NOT NULL); INSERT INTO metadata_catalog (owner) VALUES ('runtime'); CREATE TABLE _audit_events (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL); INSERT INTO _audit_events (id, workspace_id) VALUES ('runtime-event', 'default')`); err != nil {
		t.Fatal(err)
	}
	factory := identitymodule.NewFactory(identitymodule.Options{DatabaseDriver: "sqlite", DatabasePath: dbPath})
	binding, err := factory.OpenWithDatabase(t.Context(), identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "crm"}, identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: dbPath})
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
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id = 'default'`).Scan(&runtimeAuditEvents); err != nil || runtimeAuditEvents != 1 {
		t.Fatalf("Runtime-owned workspace table changed: count=%d err=%v", runtimeAuditEvents, err)
	}
	var identityTables int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'domainry_identity_%'`).Scan(&identityTables); err != nil || identityTables == 0 {
		t.Fatalf("borrowed Identity tables=%d err=%v", identityTables, err)
	}
}
