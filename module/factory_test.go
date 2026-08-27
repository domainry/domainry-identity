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
	identitymanagement "github.com/domainry/domainry-identity-sdk/management"
	identitymodulehost "github.com/domainry/domainry-identity-sdk/modulehost"
	identitymodule "github.com/domainry/domainry-identity/module"
)

type testHost struct {
	db             *sql.DB
	migrationCalls int
	clock          identitysdk.Clock
	application    identitysdk.ApplicationRef
}

func (host *testHost) Clock() identitysdk.Clock {
	if host.clock != nil {
		return host.clock
	}
	return testClock{now: time.Now().UTC()}
}
func (*testHost) Audit() identitysdk.AuditAppender { return testAudit{} }
func (host *testHost) Application() identitysdk.ApplicationRef {
	return host.application
}
func (host *testHost) IdentityDatabase(context.Context) (identitymodulehost.Database, error) {
	return identitymodulehost.Database{DB: host.db, Driver: "sqlite"}, nil
}
func (host *testHost) RegisterIdentityMigrations(ctx context.Context, migrations []identitymodulehost.Migration) error {
	for _, migration := range migrations {
		host.migrationCalls++
		if err := migration.Up(ctx, identitymodulehost.Database{DB: host.db, Driver: "sqlite"}); err != nil {
			return err
		}
	}
	return nil
}

type testClock struct{ now time.Time }

func (clock testClock) Now() time.Time { return clock.now }

type testAudit struct{}

func (testAudit) AppendIdentityAudit(context.Context, identitysdk.AuditEvent) error { return nil }

func TestFactoryOpensDirectSDKBinding(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve module test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), ".."))
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_DRIVER", "sqlite")
	t.Setenv("APP_DB_PATH", filepath.Join(t.TempDir(), "identity.db"))
	t.Setenv("TEMPLATE_MANIFEST", filepath.Join(projectRoot, "domainry.template.json"))
	t.Setenv("AUTH_AUDIENCE", "must-not-win-over-host-application")
	hostDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "module-host.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hostDB.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	host := &testHost{db: hostDB, clock: testClock{now: now}, application: identitysdk.ApplicationRef{WorkspaceID: "default", ApplicationKey: "orders-runtime", RedirectURLs: []string{"http://localhost:3100/auth/callback"}}}
	factory := identitymodule.NewFactory(identitymodule.Options{IdentityVersion: "test"})
	binding, err := factory.Open(t.Context(), host)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Descriptor().Mode != identitysdk.DeploymentModeModule {
		t.Fatalf("mode = %q", binding.Descriptor().Mode)
	}
	if binding.Descriptor().Audience != "orders-runtime" {
		t.Fatalf("module audience=%q want host application audience", binding.Descriptor().Audience)
	}
	if host.migrationCalls != 1 {
		t.Fatalf("Identity host migration calls=%d", host.migrationCalls)
	}
	managementProvider, ok := binding.(identitymanagement.Provider)
	if !ok {
		t.Fatal("module Binding does not expose its management Surface")
	}
	managementSurface := managementProvider.ManagementSurface()
	if managementSurface == nil || managementSurface.Handler() == nil || managementSurface.ContractVersion() != identitymanagement.ContractVersion {
		t.Fatalf("invalid module management Surface %#v", managementSurface)
	}
	routes := managementSurface.Routes()
	if len(routes) == 0 {
		t.Fatal("module management Surface has no routes")
	}
	foundUsers := false
	for _, route := range routes {
		if route.Pattern == "GET /identity/users" {
			foundUsers = true
		}
		if route.Pattern == "POST /auth/login" || route.Pattern == "GET /health" {
			t.Fatalf("standalone-only route leaked into module management Surface: %q", route.Pattern)
		}
	}
	if !foundUsers {
		t.Fatal("module management Surface is missing GET /identity/users")
	}
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
	var revisionCount int
	if err := hostDB.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM identity_authorization_catalog_revisions WHERE workspace_id = ? AND application_key = ?`, "default", "orders-runtime").Scan(&revisionCount); err != nil || revisionCount != 2 {
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

	reopened, err := factory.Open(t.Context(), host)
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

func TestFactoryRejectsHostWithoutModuleCapabilities(t *testing.T) {
	if _, err := identitymodule.NewFactory(identitymodule.Options{}).Open(t.Context(), nil); err == nil {
		t.Fatal("module factory accepted host without database and migration capabilities")
	}
}

var _ identitymodulehost.Host = (*testHost)(nil)
