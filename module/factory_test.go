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
	"slices"
	"strings"
	"testing"
	"time"

	dataexchangemodulehost "github.com/domainry/domainry-data-exchange-sdk/modulehost"
	actioncontract "github.com/domainry/domainry-foundation/action"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitycontracttest "github.com/domainry/domainry-identity-sdk/contracttest"
	identityhttpapi "github.com/domainry/domainry-identity-sdk/httpapi"
	identitymodulehost "github.com/domainry/domainry-identity-sdk/modulehost"
	identitymodule "github.com/domainry/domainry-identity/module"
	ormsqlite "github.com/domainry/domainry-orm/sqlite"
)

type testClock struct{ now time.Time }

func (clock testClock) Now() time.Time { return clock.now }

type testWorkspaceIdentityUsageAuthority struct {
	authorizations int
}

func (authority *testWorkspaceIdentityUsageAuthority) AuthorizeWorkspaceIdentityUsage(_ context.Context, request identitymodulehost.WorkspaceIdentityUsageAuthorizationRequest) (identitymodulehost.WorkspaceIdentityUsageGrant, error) {
	authority.authorizations++
	if request.AccessToken != "installation-usage-token" || request.PermissionKey != identitysdk.WorkspaceIdentityUsageAggregatePermission {
		return identitymodulehost.WorkspaceIdentityUsageGrant{}, errors.New("installation usage denied")
	}
	return identitymodulehost.WorkspaceIdentityUsageGrant{
		InstallationID: "installation-1", ApplicationKey: "crm", SubjectID: "billing-service",
		AuditWorkspaceID: "workspace-primary", PermissionKey: request.PermissionKey,
		AuthorizationRevision: "authorization-1", AuthorizationAuditID: fmt.Sprintf("authority-audit-%d", authority.authorizations),
	}, nil
}

func (*testWorkspaceIdentityUsageAuthority) ListAuthorizedWorkspaceIdentityUsage(_ context.Context, _ identitymodulehost.WorkspaceIdentityUsageGrant, query identitymodulehost.WorkspaceIdentityUsageCatalogQuery) (identitymodulehost.WorkspaceIdentityUsageCatalogPage, error) {
	if query.Limit < 1 || query.Limit > identitysdk.WorkspaceIdentityUsageMaxPageSize+1 || query.ExpectedCatalogRevision != "" && query.ExpectedCatalogRevision != "catalog-1" {
		return identitymodulehost.WorkspaceIdentityUsageCatalogPage{}, errors.New("invalid catalog query")
	}
	entries := []identitymodulehost.WorkspaceIdentityUsageCatalogEntry{
		{WorkspaceID: "workspace-primary", Status: identitymodulehost.WorkspaceIdentityUsageCatalogActive, Known: true, Authorized: true},
		{WorkspaceID: "workspace-secondary", Status: identitymodulehost.WorkspaceIdentityUsageCatalogActive, Known: true, Authorized: true},
	}
	page := identitymodulehost.WorkspaceIdentityUsageCatalogPage{CatalogRevision: "catalog-1"}
	for _, entry := range entries {
		if entry.WorkspaceID > query.AfterWorkspaceID {
			page.Workspaces = append(page.Workspaces, entry)
		}
		if len(page.Workspaces) == query.Limit {
			break
		}
	}
	return page, nil
}

func (*testWorkspaceIdentityUsageAuthority) ResolveAuthorizedWorkspaceIdentityUsage(_ context.Context, _ identitymodulehost.WorkspaceIdentityUsageGrant, request identitymodulehost.WorkspaceIdentityUsageCatalogResolve) (identitymodulehost.WorkspaceIdentityUsageCatalogEntry, error) {
	for workspaceCode, workspaceID := range map[string]string{"primary": "workspace-primary", "secondary": "workspace-secondary"} {
		if request.WorkspaceCode == workspaceCode {
			return identitymodulehost.WorkspaceIdentityUsageCatalogEntry{WorkspaceID: workspaceID, Status: identitymodulehost.WorkspaceIdentityUsageCatalogActive, Known: true, Authorized: true}, nil
		}
	}
	return identitymodulehost.WorkspaceIdentityUsageCatalogEntry{}, errors.New("unknown Workspace usage scope")
}

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
	calls     []testEmbeddedMigrationCall
	skipApply bool
}

func (registrar *testEmbeddedMigrationRegistrar) ApplyOwnedMigration(ctx context.Context, owner string, version uint, name, _ string, apply func(context.Context) error) error {
	registrar.calls = append(registrar.calls, testEmbeddedMigrationCall{owner: owner, version: version, name: name})
	if registrar.skipApply {
		return nil
	}
	return apply(ctx)
}

type testModuleMigrationRegistrar struct {
	database *sql.DB
	applied  map[string]bool
	owners   []string
}

func (r *testModuleMigrationRegistrar) Driver() string { return "sqlite" }
func (r *testModuleMigrationRegistrar) Schema() string { return "" }
func (r *testModuleMigrationRegistrar) ApplyOwnedMigrations(ctx context.Context, owner string, migrations []identitymodulehost.SchemaMigration) error {
	r.owners = append(r.owners, owner)
	if r.applied == nil {
		r.applied = map[string]bool{}
	}
	for _, migration := range migrations {
		key := fmt.Sprintf("%s:%d:%s", owner, migration.Version, migration.Name)
		if r.applied[key] {
			continue
		}
		tx, err := r.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, statement := range migration.Statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		r.applied[key] = true
	}
	return nil
}

func TestFactoryInitializesNestedBindingsWhenHostSkipsAppliedIdentityMigration(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "project.db")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	application := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "crm"}
	modules := &testModuleMigrationRegistrar{database: db}
	firstMigration := &testEmbeddedMigrationRegistrar{}
	handle := identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: databasePath, Migrations: firstMigration, ModuleMigrations: modules}
	first, err := identitymodule.NewFactory(identitymodule.Options{DatabaseDriver: "sqlite", DatabasePath: databasePath}).OpenWithDatabase(t.Context(), application, handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	secondMigration := &testEmbeddedMigrationRegistrar{skipApply: true}
	handle.Migrations = secondMigration
	second, err := identitymodule.NewFactory(identitymodule.Options{DatabaseDriver: "sqlite", DatabasePath: databasePath}).OpenWithDatabase(t.Context(), application, handle)
	if err != nil {
		t.Fatalf("reopen after applied host migration: %v", err)
	}
	if err := second.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(secondMigration.calls) != 1 || !slices.Contains(modules.owners, "metadata") || !slices.Contains(modules.owners, "audit") {
		t.Fatalf("outer calls=%#v nested owners=%#v", secondMigration.calls, modules.owners)
	}
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
	operationsDB, err := sql.Open("sqlite", moduleDBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = operationsDB.Close() })
	installAndBindModuleSharedOperations(t, operationsDB, binding)
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
	challenge, ok := binding.(identitysdk.ChallengeAuthenticationBinding)
	if !ok || challenge.ChallengeAuthentication() == nil {
		t.Fatal("embedded Identity binding does not expose challenge-aware authentication")
	}
	assurance, ok := binding.(identitysdk.ActionAssuranceBinding)
	if !ok || assurance.ActionAssurance() == nil {
		t.Fatal("embedded Identity binding does not expose action assurance")
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
		t.Fatal("module Binding does not expose its HTTP Adapters")
	}
	adapters := httpProvider.HTTPAdapters()
	if len(adapters) != 2 {
		t.Fatalf("HTTP adapter count=%d", len(adapters))
	}
	foundUsers, foundLogin := false, false
	for _, adapter := range adapters {
		if adapter == nil || adapter.Handler() == nil || adapter.ContractVersion() != identityhttpapi.ContractVersion {
			t.Fatalf("invalid module HTTP Adapter %#v", adapter)
		}
		for _, route := range adapter.Routes() {
			if route.Pattern() == "GET /identity/users" {
				foundUsers = true
			}
			if route.Pattern() == "POST /auth/login" {
				foundLogin = true
			}
			if route.Pattern() == "GET /health" {
				t.Fatalf("standalone-only route leaked into module HTTP Adapter: %q", route.Pattern())
			}
		}
	}
	if !foundUsers || !foundLogin {
		t.Fatalf("module adapters users=%v login=%v", foundUsers, foundLogin)
	}
	mounted := http.NewServeMux()
	mountedPatterns := map[string]string{}
	for _, adapter := range adapters {
		for _, route := range adapter.Routes() {
			pattern := route.Pattern()
			if owner, duplicate := mountedPatterns[pattern]; duplicate {
				t.Fatalf("module route %q is duplicated by %q and %q", pattern, owner, adapter.Name())
			}
			mountedPatterns[pattern] = adapter.Name()
			mounted.Handle(pattern, adapter.Handler())
		}
	}
	for pattern, wantExposure := range map[string]identityhttpapi.Exposure{
		"GET /.well-known/jwks.json":                            identityhttpapi.ExposurePublic,
		"GET /.well-known/openid-configuration":                 identityhttpapi.ExposurePublic,
		"POST /auth/login":                                      identityhttpapi.ExposurePublic,
		"POST /auth/totp":                                       identityhttpapi.ExposurePublic,
		"POST /auth/guest":                                      identityhttpapi.ExposurePublic,
		"POST /auth/providers/{provider}/exchange":              identityhttpapi.ExposurePublic,
		"GET /auth/providers/{provider}/setup-check":            identityhttpapi.ExposureManagement,
		"PUT /auth/providers/{provider}/setup":                  identityhttpapi.ExposureManagement,
		"GET /auth/external-accounts":                           identityhttpapi.ExposurePublic,
		"POST /auth/external-accounts/{provider}/bind":          identityhttpapi.ExposurePublic,
		"DELETE /auth/external-accounts/{provider}/{accountID}": identityhttpapi.ExposurePublic,
		"GET /auth/me":                                          identityhttpapi.ExposurePublic,
		"PATCH /auth/me":                                        identityhttpapi.ExposurePublic,
		"GET /auth/role-options":                                identityhttpapi.ExposurePublic,
		"GET /auth/role-requests":                               identityhttpapi.ExposurePublic,
		"POST /auth/role-requests":                              identityhttpapi.ExposurePublic,
		"POST /auth/reset-password":                             identityhttpapi.ExposureManagement,
	} {
		owner, ok := mountedPatterns[pattern]
		if !ok {
			t.Fatalf("module route %q is not exported", pattern)
		}
		foundExposure := false
		for _, adapter := range adapters {
			if adapter.Name() != owner {
				continue
			}
			for _, route := range adapter.Routes() {
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
	permissionDefinitions := []identitysdk.PermissionDefinition{{PermissionKey: "customer.read", ResourceKey: "customer", OperationKey: "read", Label: "Read customers", Category: "Orders", SourceKind: "object_action"}}
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
		Roles: []identitysdk.ProjectRoleDefinition{
			{Key: "project_viewer", Name: "Project Viewer", Permissions: []identitysdk.ProjectRolePermission{{PermissionKey: "customer.read", DataScope: identitysdk.DataScopeAll}}, Audience: "any", AssignmentMode: "manual", RiskLevel: "normal", SchemaHash: strings.Repeat("a", 64)},
			{Key: "customer_sync_service", Name: "Customer sync service", Permissions: []identitysdk.ProjectRolePermission{{PermissionKey: "customer.read", DataScope: identitysdk.DataScopeAll}}, Audience: "service", AssignmentMode: "system_managed", RiskLevel: "normal", SchemaHash: strings.Repeat("b", 64)},
		},
	})
	if err != nil || roleReceipt.Published != 2 || len(roleReceipt.SHA256) != 64 {
		t.Fatalf("project role receipt=%#v err=%v", roleReceipt, err)
	}
	repeatedRoleReceipt, err := rolePublisher.PublishProjectRoles(t.Context(), identitysdk.ProjectRoleCatalog{
		Application: application,
		Roles: []identitysdk.ProjectRoleDefinition{
			{Key: "project_viewer", Name: "Project Viewer", Permissions: []identitysdk.ProjectRolePermission{{PermissionKey: "customer.read", DataScope: identitysdk.DataScopeAll}}, Audience: "any", AssignmentMode: "manual", RiskLevel: "normal", SchemaHash: strings.Repeat("a", 64)},
			{Key: "customer_sync_service", Name: "Customer sync service", Permissions: []identitysdk.ProjectRolePermission{{PermissionKey: "customer.read", DataScope: identitysdk.DataScopeAll}}, Audience: "service", AssignmentMode: "system_managed", RiskLevel: "normal", SchemaHash: strings.Repeat("b", 64)},
		},
	})
	if err != nil || repeatedRoleReceipt != roleReceipt {
		t.Fatalf("idempotent project role receipt=%#v want=%#v err=%v", repeatedRoleReceipt, roleReceipt, err)
	}
	if _, err := rolePublisher.PublishProjectRoles(t.Context(), identitysdk.ProjectRoleCatalog{Application: identitysdk.ApplicationRef{WorkspaceID: "other", ApplicationKey: application.ApplicationKey}}); err == nil {
		t.Fatal("cross-workspace project role publication accepted")
	}
	roles, err := binding.Projection().ListRoles(t.Context(), identitysdk.ProjectionQuery{})
	if err != nil {
		t.Fatal(err)
	}
	foundProjectRole := false
	for _, role := range roles {
		foundProjectRole = foundProjectRole || role.Key == "project_viewer"
	}
	if !foundProjectRole {
		t.Fatalf("project role missing from projection: %#v", roles)
	}
	workloadBinding, ok := binding.(identitysdk.WorkflowWorkloadIdentityBinding)
	if !ok || workloadBinding.WorkflowWorkloads() == nil {
		t.Fatal("module Binding does not expose Workflow workload identity")
	}
	workloadSpec := identitysdk.WorkflowWorkloadBindingSpec{WorkflowKey: "customer_sync", DefinitionVersionID: "workflow-version-1", DefinitionVersion: 1, RoleKey: "customer_sync_service", ActionKeys: []string{"customer.read"}}
	digest, err := identitysdk.WorkflowWorkloadReleaseDigest([]identitysdk.WorkflowWorkloadBindingSpec{workloadSpec})
	if err != nil {
		t.Fatal(err)
	}
	workloadRequest := identitysdk.ApplyWorkflowWorkloadBindingsRequest{
		Application: identitysdk.ApplicationScope{WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey},
		ReleaseID:   identitysdk.WorkflowWorkloadReleaseID(digest), ReleaseDigest: digest, Bindings: []identitysdk.WorkflowWorkloadBindingSpec{workloadSpec},
	}
	applied, err := workloadBinding.WorkflowWorkloads().ApplyWorkflowWorkloadBindings(t.Context(), workloadRequest)
	if err != nil || len(applied.Bindings) != 1 || applied.Bindings[0].SubjectID != "workflow:customer_sync" || applied.Bindings[0].SourceKind != "deployment_control_plane" || applied.Bindings[0].SourceID != "orders-runtime" {
		t.Fatalf("workflow workload apply=%+v err=%v", applied, err)
	}
	resolution, err := binding.Principals().Resolve(t.Context(), identitysdk.PrincipalResolutionRequest{
		SubjectID: "workflow:customer_sync", RoleKey: "customer_sync_service",
		Workload: &identitysdk.WorkflowWorkloadResolution{WorkflowKey: "customer_sync", DefinitionVersionID: "workflow-version-1", DefinitionVersion: 1, ReleaseID: workloadRequest.ReleaseID, ReleaseDigest: digest, TaskID: "task-1", SourceEventID: "event-1", InitiatorSubjectID: "member-1"},
	})
	if err != nil || !resolution.Principal.Known || resolution.Principal.Workload == nil || resolution.Principal.Workload.TaskID != "task-1" || resolution.Principal.Workload.InitiatorSubjectID != "member-1" || !slices.Contains(resolution.Principal.Permissions, "customer.read") {
		t.Fatalf("workflow workload resolution=%+v err=%v", resolution, err)
	}
	staleResolution := identitysdk.PrincipalResolutionRequest{
		SubjectID: "workflow:customer_sync", RoleKey: "customer_sync_service",
		Workload: &identitysdk.WorkflowWorkloadResolution{WorkflowKey: "customer_sync", DefinitionVersionID: "workflow-version-0", DefinitionVersion: 1, ReleaseID: workloadRequest.ReleaseID, ReleaseDigest: digest},
	}
	if _, err := binding.Principals().Resolve(t.Context(), staleResolution); err == nil || !strings.Contains(err.Error(), "version_mismatch") {
		t.Fatalf("replaced workflow version resolved: %v", err)
	}
	deniedSpec := workloadSpec
	deniedSpec.ActionKeys = []string{"customer.delete"}
	deniedDigest, err := identitysdk.WorkflowWorkloadReleaseDigest([]identitysdk.WorkflowWorkloadBindingSpec{deniedSpec})
	if err != nil {
		t.Fatal(err)
	}
	deniedRequest := workloadRequest
	deniedRequest.ReleaseDigest = deniedDigest
	deniedRequest.ReleaseID = identitysdk.WorkflowWorkloadReleaseID(deniedDigest)
	deniedRequest.Bindings = []identitysdk.WorkflowWorkloadBindingSpec{deniedSpec}
	if _, err := workloadBinding.WorkflowWorkloads().ApplyWorkflowWorkloadBindings(t.Context(), deniedRequest); err == nil || !strings.Contains(err.Error(), "action_denied") {
		t.Fatalf("workflow release with an unauthorized action was accepted: %v", err)
	}
	if unchanged, err := binding.Principals().Resolve(t.Context(), identitysdk.PrincipalResolutionRequest{
		SubjectID: "workflow:customer_sync", RoleKey: "customer_sync_service",
		Workload: &identitysdk.WorkflowWorkloadResolution{WorkflowKey: "customer_sync", DefinitionVersionID: "workflow-version-1", DefinitionVersion: 1, ReleaseID: workloadRequest.ReleaseID, ReleaseDigest: digest},
	}); err != nil || !unchanged.Principal.Known {
		t.Fatalf("rejected workload release changed the active binding: resolution=%+v err=%v", unchanged, err)
	}
	crossWorkspace := workloadRequest
	crossWorkspace.Application.WorkspaceID = "workspace-other"
	if _, err := workloadBinding.WorkflowWorkloads().ApplyWorkflowWorkloadBindings(t.Context(), crossWorkspace); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("cross-workspace workflow workload release was accepted: %v", err)
	}
	probeDB, err := sql.Open("sqlite", moduleDBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer probeDB.Close()
	for _, table := range []string{"_identity_users", "_identity_user_role_assignments"} {
		var count int
		if err := probeDB.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table+" WHERE workspace_id=? AND "+map[string]string{"_identity_users": "id", "_identity_user_role_assignments": "user_id"}[table]+"=?", "workspace-primary", "workflow:customer_sync").Scan(&count); err != nil || count != 0 {
			t.Fatalf("workflow workload leaked into %s: count=%d err=%v", table, count, err)
		}
	}
	tampered := workloadRequest
	tampered.ReleaseDigest = strings.Repeat("f", 64)
	if _, err := workloadBinding.WorkflowWorkloads().ApplyWorkflowWorkloadBindings(t.Context(), tampered); err == nil || !strings.Contains(err.Error(), "release_digest_mismatch") {
		t.Fatalf("tampered workload release accepted: %v", err)
	}
	if _, err := probeDB.ExecContext(t.Context(), `UPDATE _identity_roles SET status='disabled' WHERE workspace_id=? AND role_key=?`, "workspace-primary", "customer_sync_service"); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Principals().Resolve(t.Context(), identitysdk.PrincipalResolutionRequest{
		SubjectID: "workflow:customer_sync", RoleKey: "customer_sync_service",
		Workload: &identitysdk.WorkflowWorkloadResolution{WorkflowKey: "customer_sync", DefinitionVersionID: "workflow-version-1", DefinitionVersion: 1, ReleaseID: workloadRequest.ReleaseID, ReleaseDigest: digest},
	}); err == nil || !strings.Contains(err.Error(), "role_unavailable") {
		t.Fatalf("workflow workload resolved through a disabled role: %v", err)
	}
	if _, err := probeDB.ExecContext(t.Context(), `UPDATE _identity_roles SET status='active' WHERE workspace_id=? AND role_key=?`, "workspace-primary", "customer_sync_service"); err != nil {
		t.Fatal(err)
	}
	if _, err := probeDB.ExecContext(t.Context(), `UPDATE _identity_workflow_workload_bindings SET role_key='project_viewer' WHERE workspace_id=? AND application_key=? AND workflow_key=?`, "workspace-primary", "orders-runtime", "customer_sync"); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Principals().Resolve(t.Context(), identitysdk.PrincipalResolutionRequest{
		SubjectID: "workflow:customer_sync", RoleKey: "customer_sync_service",
		Workload: &identitysdk.WorkflowWorkloadResolution{WorkflowKey: "customer_sync", DefinitionVersionID: "workflow-version-1", DefinitionVersion: 1, ReleaseID: workloadRequest.ReleaseID, ReleaseDigest: digest},
	}); err == nil || !strings.Contains(err.Error(), "role_mismatch") {
		t.Fatalf("workflow workload resolved through a changed binding role: %v", err)
	}
	if _, err := probeDB.ExecContext(t.Context(), `DELETE FROM _identity_workflow_workload_bindings WHERE workspace_id=? AND application_key=? AND workflow_key=?`, "workspace-primary", "orders-runtime", "customer_sync"); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Principals().Resolve(t.Context(), identitysdk.PrincipalResolutionRequest{
		SubjectID: "workflow:customer_sync", RoleKey: "customer_sync_service",
		Workload: &identitysdk.WorkflowWorkloadResolution{WorkflowKey: "customer_sync", DefinitionVersionID: "workflow-version-1", DefinitionVersion: 1, ReleaseID: workloadRequest.ReleaseID, ReleaseDigest: digest},
	}); err == nil || !strings.Contains(err.Error(), "not_found") {
		t.Fatalf("deleted workflow workload binding still resolved: %v", err)
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
	if mountedPatterns["POST /auth/totp"] != "browser_authentication" {
		t.Fatalf("TOTP route has unexpected owner %q", mountedPatterns["POST /auth/totp"])
	}
	totpStatus := httptest.NewRecorder()
	totpRequest := httptest.NewRequest(http.MethodPost, "/auth/totp", strings.NewReader(`{"operation":"status"}`))
	totpRequest.Header.Set("Content-Type", "application/json")
	totpRequest.Header.Set("Authorization", "Bearer "+adminSession.AccessToken)
	mounted.ServeHTTP(totpStatus, totpRequest)
	if totpStatus.Code != http.StatusOK || !strings.Contains(totpStatus.Body.String(), `"enabled":false`) {
		t.Fatalf("mounted TOTP status=%d body=%s", totpStatus.Code, totpStatus.Body.String())
	}
	embeddedRegistry := actioncontract.NewRegistry()
	if err := embeddedRegistry.Register(actioncontract.ActionDefinition{
		Key: "customer.read", Owner: "application:orders-runtime", SourceKind: "object_action",
		CapabilityKey: "customer", CapabilityLabel: "Customer", OperationKey: "read", OperationLabel: "Read customers", Label: "Read customers",
		Exposures:     []actioncontract.Exposure{actioncontract.ExposureManagement},
		Authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticated},
		NonHTTP:       []actioncontract.NonHTTPBinding{{Kind: "rpc", InvocationKey: "customer.read"}},
		Permission: &actioncontract.PermissionDefinition{
			Key: "customer.read", Owner: "application:orders-runtime", ResourceKey: "customer", OperationKey: "read",
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
		t.Fatalf("mounted management reset-password status=%d body=%s", reset.Code, reset.Body.String())
	}
	for _, resourceType := range []string{"role", "permission"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/metadata/definitions/"+resourceType, nil)
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
	managementAdapter := adapters[1]
	response := httptest.NewRecorder()
	managementAdapter.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/identity/users", nil))
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
		Resource: "identity.users", Action: "list", DataAllowed: true,
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
	if len(registrar.calls) != 1 || registrar.calls[0] != (testEmbeddedMigrationCall{owner: "identity", version: 16, name: "shared_manifest_catalog"}) {
		t.Fatalf("host migration calls=%#v", registrar.calls)
	}
}

func TestFactoryEmbeddedOrganizationUnitDeliveryRollsBackWithHostTransaction(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("AUTH_JWT_SECRET", "module-organization-unit-secret")
	t.Setenv("AUTH_DEFAULT_PASSWORD", "Domainry@2026")
	databasePath := filepath.Join(t.TempDir(), "organization-unit-project.db")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(4)
	handle := identitysdk.DatabaseHandle{Pool: db, Driver: "sqlite", FilePath: databasePath, Migrations: &testEmbeddedMigrationRegistrar{}}
	application := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime-a"}
	factory := identitymodule.NewFactory(identitymodule.Options{DatabaseDriver: "sqlite", DatabasePath: databasePath})
	binding, err := factory.OpenWithDatabase(t.Context(), application, handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(t.Context()) })
	installAndBindModuleSharedOperations(t, db, binding)
	if _, err := binding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: application}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO _identity_organization_units (id, workspace_id, code, name, sibling_key, node_type, parent_id, path, ancestor_ids, depth, sort_order, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"company-a", "workspace-primary", "COMPANY-A", "Company A", "company-a-sibling-key", "company", nil, "/company-a", "[]", 0, 0, "active", "now", "now"); err != nil {
		t.Fatal(err)
	}

	otherApplication := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime-b"}
	otherBinding, err := factory.OpenWithDatabase(t.Context(), otherApplication, handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = otherBinding.Close(t.Context()) })
	if _, err := otherBinding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: otherApplication}); err != nil {
		t.Fatal(err)
	}
	otherSession, err := otherBinding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{
		WorkspaceID: otherApplication.WorkspaceID, ApplicationKey: otherApplication.ApplicationKey, Login: "admin@example.com", Password: "Domainry@2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	embedded, ok := binding.(identitymodule.EmbeddedOrganizationUnitDeliveryBinding)
	if !ok {
		t.Fatal("Factory binding omitted EmbeddedOrganizationUnitDeliveryBinding")
	}
	mismatchTransaction, err := ormsqlite.NewProfile().BeginWrite(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	mismatchDelivery, err := embedded.OrganizationUnitDeliveryUnitOfWorkBinder().BindOrganizationUnitDeliveryUnitOfWork(identitysdk.EmbeddedTransaction{Executor: mismatchTransaction})
	if err != nil {
		_ = mismatchTransaction.Rollback(t.Context())
		t.Fatal(err)
	}
	if _, err := mismatchDelivery.ResolveOrganizationUnit(t.Context(), identitymodule.OrganizationUnitResolveRequest{
		ContractVersion: identitymodule.OrganizationUnitDeliveryContractVersionV1, AccessToken: otherSession.AccessToken,
		OrganizationID: "company-a", NodeType: identitymodule.OrganizationUnitDepartment,
	}); err == nil {
		_ = mismatchTransaction.Rollback(t.Context())
		t.Fatal("cross-application token was accepted")
	} else {
		var sdkErr *identitysdk.Error
		if !errors.As(err, &sdkErr) || sdkErr.Code != "identity.organization_unit_delivery_application_scope_mismatch" {
			_ = mismatchTransaction.Rollback(t.Context())
			t.Fatalf("cross-application token error=%v", err)
		}
	}
	if err := mismatchTransaction.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	session, err := binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{
		WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "admin@example.com", Password: "Domainry@2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	hostTransaction, err := ormsqlite.NewProfile().BeginWrite(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := embedded.OrganizationUnitDeliveryUnitOfWorkBinder().BindOrganizationUnitDeliveryUnitOfWork(identitysdk.EmbeddedTransaction{Executor: hostTransaction})
	if err != nil {
		_ = hostTransaction.Rollback(t.Context())
		t.Fatal(err)
	}
	created, err := delivery.CreateOrganizationUnit(t.Context(), identitymodule.OrganizationUnitDeliveryRequest{
		ContractVersion: identitymodule.OrganizationUnitDeliveryContractVersionV1,
		AccessToken:     session.AccessToken,
		IdempotencyKey:  "factory-department-rollback",
		Organization: identitymodule.OrganizationUnitCreateCandidate{
			OrganizationID: "factory-department", Code: "FACTORY-DEPARTMENT", Name: "Factory Department",
			NodeType: identitymodule.OrganizationUnitDepartment, ParentOrganizationID: "company-a", ExpectedVersion: 0,
		},
	})
	if err != nil || created.Organization.Path != "/company-a/factory-department" {
		_ = hostTransaction.Rollback(t.Context())
		t.Fatalf("Factory embedded delivery=%+v err=%v", created, err)
	}
	if err := hostTransaction.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		table, column, value string
	}{
		{table: "_identity_organization_units", column: "id", value: "factory-department"},
		{table: "_operations", column: "idempotency_key", value: "factory-department-rollback"},
		{table: "_audit_events", column: "record_id", value: "factory-department"},
	} {
		var count int
		if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+check.table+" WHERE workspace_id = ? AND "+check.column+" = ?", "workspace-primary", check.value).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rollback %s count=%d err=%v", check.table, count, err)
		}
	}
}

func TestEmbeddedWorkspaceIdentityUsageJoinsHostTransactionAndAuditsReleasedPage(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "workspace-usage-project.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(3)
	authority := &testWorkspaceIdentityUsageAuthority{}
	binding, err := identitymodule.NewFactory(identitymodule.Options{DatabaseDriver: "sqlite", DatabasePath: dbPath}).OpenWithDatabase(
		t.Context(),
		identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "crm"},
		identitysdk.DatabaseHandle{
			Pool: db, Driver: "sqlite", FilePath: dbPath, Migrations: &testEmbeddedMigrationRegistrar{},
			WorkspaceIdentityUsageAuthority: authority, WorkspaceIdentityUsageCursorKey: []byte("0123456789abcdef0123456789abcdef"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close(t.Context())
	if _, err := db.ExecContext(t.Context(), `INSERT INTO _identity_users (id, workspace_id, name, email, account_type, reporting_path, status, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"secondary-service", "workspace-secondary", "Service", "service@example.test", "service", "/secondary-service", "active", 1, "now", "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO _identity_users (id, workspace_id, name, email, account_type, reporting_path, status, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"secondary-automation", "workspace-secondary", "Automation", "automation@example.test", "automation", "/secondary-automation", "disabled", 1, "now", "now"); err != nil {
		t.Fatal(err)
	}
	embedded, ok := binding.(identitysdk.EmbeddedWorkspaceIdentityUsageBinding)
	if !ok {
		t.Fatal("embedded binding does not expose the Workspace usage UoW binder")
	}

	call := func(tx *sql.Tx) identitysdk.WorkspaceIdentityUsagePage {
		t.Helper()
		aggregate, err := embedded.WorkspaceIdentityUsageUnitOfWorkBinder().BindWorkspaceIdentityUsageUnitOfWork(identitysdk.EmbeddedTransaction{Executor: tx})
		if err != nil {
			t.Fatal(err)
		}
		page, err := aggregate.ListWorkspaceIdentityUsage(t.Context(), identitysdk.WorkspaceIdentityUsageRequest{
			ContractVersion: identitysdk.CurrentWorkspaceIdentityUsageContractVersion,
			ContractHash:    identitysdk.CurrentWorkspaceIdentityUsageContractHash,
			AccessToken:     "installation-usage-token", PageSize: 10,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 2 || page.Items[0].WorkspaceID != "workspace-primary" || page.Items[1].WorkspaceID != "workspace-secondary" {
			t.Fatalf("usage page=%+v", page)
		}
		if counts := page.Items[1].Accounts; counts.ServiceAccounts != 1 || counts.AutomationAccounts != 1 || counts.ActiveHumanAccounts != 0 || counts.DisabledHumanAccounts != 0 {
			t.Fatalf("secondary counts=%+v", counts)
		}
		exact, err := aggregate.ResolveWorkspaceIdentityUsage(t.Context(), identitysdk.WorkspaceIdentityUsageResolveRequest{
			ContractVersion: identitysdk.CurrentWorkspaceIdentityUsageContractVersion,
			ContractHash:    identitysdk.CurrentWorkspaceIdentityUsageContractHash,
			AccessToken:     "installation-usage-token",
			WorkspaceCode:   "secondary",
		})
		if err != nil {
			t.Fatal(err)
		}
		if exact.WorkspaceID != "workspace-secondary" || exact.Accounts.ServiceAccounts != 1 || exact.Accounts.AutomationAccounts != 1 {
			t.Fatalf("exact usage=%+v", exact)
		}
		return page
	}

	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	call(tx)
	var transactionalAudits int
	if err := tx.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id = ? AND event = ? AND record_id = ?`, "workspace-primary", "identity.workspace_identity_usage.aggregate", "installation-1").Scan(&transactionalAudits); err != nil || transactionalAudits != 1 {
		_ = tx.Rollback()
		t.Fatalf("transactional audits=%d err=%v", transactionalAudits, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var rolledBackAudits int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE event = ? AND record_id = ?`, "identity.workspace_identity_usage.aggregate", "installation-1").Scan(&rolledBackAudits); err != nil || rolledBackAudits != 0 {
		t.Fatalf("rolled back audits=%d err=%v", rolledBackAudits, err)
	}

	tx, err = db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	call(tx)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var committedAudits int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE event = ? AND record_id = ?`, "identity.workspace_identity_usage.aggregate", "installation-1").Scan(&committedAudits); err != nil || committedAudits != 1 {
		t.Fatalf("committed audits=%d err=%v", committedAudits, err)
	}
	if authority.authorizations != 4 {
		t.Fatalf("authority audit decisions=%d want=4", authority.authorizations)
	}
}

func TestEmbeddedWorkspaceIdentityUsageRequiresStableCursorKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "workspace-usage-missing-key.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = identitymodule.NewFactory(identitymodule.Options{DatabaseDriver: "sqlite", DatabasePath: dbPath}).OpenWithDatabase(
		t.Context(),
		identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "crm"},
		identitysdk.DatabaseHandle{
			Pool: db, Driver: "sqlite", FilePath: dbPath, Migrations: &testEmbeddedMigrationRegistrar{},
			WorkspaceIdentityUsageAuthority: &testWorkspaceIdentityUsageAuthority{},
		},
	)
	var sdkError *identitysdk.Error
	if !errors.As(err, &sdkError) || sdkError.Code != "identity.workspace_usage_cursor_key_required" {
		t.Fatalf("missing cursor key err=%v", err)
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
