package module_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
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
	managementSurface := surfaces[1]
	response := httptest.NewRecorder()
	managementSurface.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/identity/users", nil))
	if response.Code == http.StatusNotFound {
		t.Fatal("module management route list points at an unregistered Handler route")
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
