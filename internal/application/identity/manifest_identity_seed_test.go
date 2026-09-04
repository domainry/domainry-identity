package identity

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
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
	byID := make(map[string]identitymodel.IdentityMenu, len(menus))
	for _, menu := range menus {
		byID[menu.ID] = menu
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
}

func stringPointerForManifestIdentitySeedTest(value string) *string {
	return &value
}
