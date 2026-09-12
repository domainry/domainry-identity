package identity

import (
	"context"
	"strings"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
)

func TestManifestIdentitySeedBuildsOrganizationHierarchyAndBootstrapUsers(t *testing.T) {
	manifest := manifestmodel.ManifestSchema{
		Roles: []identitymodel.RoleSchema{{Key: "employee", Name: "Employee"}},
		IdentityBootstrap: &identitymodel.ManifestIdentityBootstrapSchema{
			Version: "1",
			OrganizationUnits: []identitymodel.ManifestIdentityOrganizationUnitSchema{
				{ID: "company", Name: "Company"},
				{ID: "people", Name: "People", ParentID: stringPointerForManifestIdentitySeedTest("company")},
			},
			Users: []identitymodel.ManifestIdentityUserSchema{
				{ID: "manager", Name: "Manager", Email: "manager@example.com", OrgID: "people", WorkerNo: "E001", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, RoleKeys: []string{"employee"}},
				{ID: "employee", Name: "Employee", Email: "employee@example.com", OrgID: "people", SupportOrgID: "company", WorkerNo: "E002", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, RoleKeys: []string{"employee"}},
			},
		},
	}
	seed := FromManifest(manifest)
	if len(seed.OrganizationUnits) != 2 || seed.OrganizationUnits[1].Path != "/company/people" || seed.OrganizationUnits[1].Depth != 1 {
		t.Fatalf("unexpected organizationUnit hierarchy: %#v", seed.OrganizationUnits)
	}
	var employeeFound bool
	for _, user := range seed.Users {
		if user.ID == "employee" {
			employeeFound = user.Name == "Employee" && user.Email == "employee@example.com" && user.OrgID == "people" && user.SupportOrgID == "company" && user.WorkerNo == "E002" && user.WorkStatus == identitymodel.IdentityWorkActive
		}
	}
	if !employeeFound {
		t.Fatalf("bootstrap user personnel fields are wrong: users=%#v", seed.Users)
	}
}

func TestManifestIdentitySeedDoesNotInferPlatformMenusFromBusinessPermissions(t *testing.T) {
	manifest := manifestmodel.ManifestSchema{
		Roles: []identitymodel.RoleSchema{
			{Key: "ceo", Name: "CEO", Permissions: identityTestRolePermissions("identity.users.list", "workflow.definition.read", "leave_request.read")},
			{Key: "hr_manager", Name: "HR Manager", Permissions: identityTestRolePermissions("leave_request.read")},
		},
	}

	seed := FromManifest(manifest)
	assignments := map[string]bool{}
	for _, assignment := range seed.RoleMenus {
		assignments[assignment.RoleID+":"+assignment.MenuID] = true
	}
	if assignments["ceo:org_users"] || assignments["ceo:system_metadata"] || assignments["hr_manager:org_users"] {
		t.Fatalf("permissions expanded CEO menu ownership: %#v", seed.RoleMenus)
	}
	if !assignments["admin:org_users"] || !assignments["admin:system_metadata"] {
		t.Fatalf("platform administrator lost recovery menus: %#v", seed.RoleMenus)
	}
}

func TestManifestIdentitySeedMaterializesOneDefaultUserForEveryDeclaredRole(t *testing.T) {
	manifest := manifestmodel.ManifestSchema{Roles: []identitymodel.RoleSchema{
		{Key: "admin", Name: "Project administrator"},
		{Key: "system_administrator", Name: "Project system administrator"},
		{Key: "reviewer", Name: "Reviewer"},
	}}
	seed := FromManifest(manifest)
	users := map[string]bool{}
	for _, user := range seed.Users {
		users[user.ID] = true
	}
	roleUsers := map[string]string{}
	for _, assignment := range seed.UserRoles {
		if roleUsers[assignment.RoleID] == "" {
			roleUsers[assignment.RoleID] = assignment.UserID
		}
	}
	for _, roleKey := range []string{"admin", "system_administrator", "reviewer"} {
		userID := roleUsers[roleKey]
		if userID == "" || !users[userID] {
			t.Fatalf("declared role %q has no materialized bootstrap user: users=%#v assignments=%#v", roleKey, seed.Users, seed.UserRoles)
		}
	}
	if roleUsers["admin"] != "admin" || roleUsers["system_administrator"] != "system_administrator_user" || roleUsers["reviewer"] != "reviewer_user" {
		t.Fatalf("role bootstrap identities are not deterministic: %#v", roleUsers)
	}
}

func TestManifestIdentitySeedDoesNotExpandWorkspaceCapabilityIntoPlatformMenus(t *testing.T) {
	manifest := manifestmodel.ManifestSchema{
		Roles: []identitymodel.RoleSchema{
			{Key: "runtime_admin", Name: "Runtime Administrator", Permissions: identityTestRolePermissions(" workspace.ADMIN ")},
			{Key: "business_manager", Name: "Business Manager", Permissions: identityTestRolePermissions("identity.users.list")},
		},
	}

	seed := FromManifest(manifest)
	assignments := map[string]bool{}
	for _, assignment := range seed.RoleMenus {
		assignments[assignment.RoleID+":"+assignment.MenuID] = true
	}
	if assignments["runtime_admin:org_users"] || assignments["runtime_admin:system_metadata"] {
		t.Fatalf("workspace capability expanded into platform menus: %#v", seed.RoleMenus)
	}
	if assignments["business_manager:org_users"] {
		t.Fatalf("ordinary business permission expanded platform menu ownership: %#v", seed.RoleMenus)
	}
}

func TestGeneratedIdentityMenusDoNotPublishBusinessDataOperationsInManagement(t *testing.T) {
	for _, menu := range generatedIdentityMenus() {
		if menu.Key == "system_import_export" || menu.Route == "/admin/system/import-export" {
			t.Fatalf("Tenant Admin seed still owns Business import/export menu: %+v", menu)
		}
	}
}

func TestGeneratedIdentityMenusDeclareValidParentChains(t *testing.T) {
	menus := generatedIdentityMenus()
	if len(menus) != 31 {
		t.Fatalf("platform Admin menu count=%d want=31 (6 groups + 25 workspaces)", len(menus))
	}
	byID := make(map[string]identitymodel.IdentityMenu, len(menus))
	routes := map[string]bool{}
	for _, menu := range menus {
		byID[menu.ID] = menu
		if menu.Route != "" {
			routes[menu.Route] = true
		}
	}
	for _, menu := range menus {
		if menu.ParentID == "" {
			continue
		}
		_, ok := byID[menu.ParentID]
		if !ok {
			t.Fatalf("menu %q parent %q missing", menu.Key, menu.ParentID)
		}
	}
	wantRoutes := []string{
		"/admin/security/accounts", "/admin/org/organization-units", "/admin/org/roles",
		"/admin/security/access-governance", "/admin/org/field-permissions", "/admin/org/menus",
		"/admin/system/metadata", "/admin/system/domain-impact", "/admin/system/dictionaries", "/admin/system/actions",
		"/admin/system/workflows", "/admin/system/workflow-processes", "/admin/system/automation-rules",
		"/admin/system/scheduler", "/admin/system/scheduler-operations",
		"/admin/system/connectors", "/admin/system/integration-activity", "/admin/system/notifications",
		"/admin/system/audit", "/admin/system/lifecycle", "/admin/system/privacy-requests",
		"/admin/system", "/admin/system/capability-status", "/admin/system/operations", "/admin/system/agent-operations",
	}
	if len(routes) != len(wantRoutes) {
		t.Fatalf("platform Admin routed menu count=%d want=%d: %#v", len(routes), len(wantRoutes), routes)
	}
	for _, route := range wantRoutes {
		if !routes[route] {
			t.Fatalf("platform Admin route %q is not seeded", route)
		}
		if permissions, ok := platformAdminPagePermissions(route); !ok || len(permissions) == 0 {
			t.Fatalf("platform Admin route %q has no menu permission contract", route)
		}
	}
}

func stringPointerForManifestIdentitySeedTest(value string) *string {
	return &value
}

// The real repository's global index protects the write; this verifies seed
// selection preserves existing credentials and explicit administrator input.
type loginSeedStore struct {
	identityrepository.IdentitySeedRepository
	existing map[string]identitymodel.IdentityUser
	occupied map[string]bool
}

func (s loginSeedStore) GetIdentityUser(_ context.Context, workspace, id string) (identitymodel.IdentityUser, bool, error) {
	u, ok := s.existing[workspace+"/"+id]
	return u, ok, nil
}
func (s loginSeedStore) GlobalLoginNameAvailable(_ context.Context, _, _, login string) (bool, error) {
	return !s.occupied[strings.ToLower(strings.TrimSpace(login))], nil
}
func TestGeneratedSeedLoginNamesAvoidGlobalDuplicatesAndSurviveResync(t *testing.T) {
	seed := Seed{Users: []identitymodel.IdentityUser{{ID: "admin", Email: "admin@example.com"}}}
	store := loginSeedStore{existing: map[string]identitymodel.IdentityUser{}, occupied: map[string]bool{}}
	a, err := scopeGeneratedSeedLoginNames(t.Context(), store, manifestmodel.ManifestSchema{}, seed, "a")
	if err != nil || a.Users[0].Email != "admin@example.com" {
		t.Fatal("first seed login changed", err)
	}
	store.occupied[a.Users[0].Email] = true
	b, err := scopeGeneratedSeedLoginNames(t.Context(), store, manifestmodel.ManifestSchema{}, seed, "b")
	if err != nil || b.Users[0].Email == a.Users[0].Email {
		t.Fatal("B reused A login", err)
	}
	store.existing["b/admin"] = b.Users[0]
	store.occupied[b.Users[0].Email] = true
	again, err := scopeGeneratedSeedLoginNames(t.Context(), store, manifestmodel.ManifestSchema{}, seed, "b")
	if err != nil || again.Users[0].Email != b.Users[0].Email {
		t.Fatal("resync changed B login", err)
	}
	explicit := manifestmodel.ManifestSchema{Users: []identitymodel.ManifestIdentityUserSchema{{ID: "admin", Email: "admin@example.com"}}}
	requested, err := scopeGeneratedSeedLoginNames(t.Context(), store, explicit, seed, "c")
	if err != nil || requested.Users[0].Email != "admin@example.com" {
		t.Fatal("explicit input was silently renamed", err)
	}
}
