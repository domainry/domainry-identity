package identity

import (
	"os"
	"testing"

	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestHRManifestDeclaresEmployeeReportingLine(t *testing.T) {
	manifest, err := loadIdentitySeedTestManifest("../../domain/manifest/testdata/manifests/identity-workforce.json")
	if err != nil {
		t.Fatal(err)
	}
	seed := FromManifest(manifest)
	found := 0
	for _, assignment := range seed.WorkforceAssignments {
		if assignment.WorkforceProfileID != "employee_user_workforce" {
			continue
		}
		found++
		if assignment.ManagerWorkforceProfileID != "line_manager_user_workforce" {
			t.Fatalf("employee workforce manager = %q, want line_manager_user_workforce", assignment.ManagerWorkforceProfileID)
		}
	}
	if found != 1 {
		t.Fatalf("employee_user seed count = %d, want 1", found)
	}
}

func loadIdentitySeedTestManifest(path string) (manifestmodel.ManifestSchema, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	manifest, _, err := manifestmodel.DecodeManifest(raw)
	return manifest, err
}

func TestManifestIdentitySeedBuildsDepartmentHierarchyAndBootstrapUsers(t *testing.T) {
	manifest := manifestmodel.ManifestSchema{
		Roles: []identitymodel.RoleSchema{{Key: "employee", Name: "Employee"}},
		IdentityBootstrap: &identitymodel.ManifestIdentityBootstrapSchema{
			Version: "1",
			Departments: []identitymodel.ManifestIdentityDepartmentSchema{
				{ID: "company", Name: "Company"},
				{ID: "people", Name: "People", ParentID: stringPointerForManifestIdentitySeedTest("company")},
			},
			Users: []identitymodel.ManifestIdentityUserSchema{
				{ID: "manager", Name: "Manager", Email: "manager@example.com", RoleKeys: []string{"employee"}},
				{ID: "employee", Name: "Employee", Email: "employee@example.com", RoleKeys: []string{"employee"}},
			},
			WorkforceProfiles: []identitymodel.ManifestIdentityWorkforceProfileSchema{
				{ID: "manager_workforce", OrganizationID: "workspace-primary", IdentityUserID: "manager", WorkerNo: "manager", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, PrimaryAssignmentID: "manager_primary"},
				{ID: "employee_workforce", OrganizationID: "workspace-primary", IdentityUserID: "employee", WorkerNo: "employee", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, PrimaryAssignmentID: "employee_primary"},
			},
			WorkforceAssignments: []identitymodel.ManifestIdentityWorkforceAssignmentSchema{
				{ID: "manager_primary", WorkforceProfileID: "manager_workforce", OrganizationUnitID: "people", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
				{ID: "employee_primary", WorkforceProfileID: "employee_workforce", OrganizationUnitID: "people", ManagerWorkforceProfileID: "manager_workforce", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
			},
		},
	}
	seed := FromManifest(manifest)
	if len(seed.Departments) != 2 || seed.Departments[1].Path != "/company/people" || seed.Departments[1].Depth != 1 {
		t.Fatalf("unexpected department hierarchy: %#v", seed.Departments)
	}
	var employeeAccountFound, employeeWorkforceFound bool
	for _, user := range seed.Users {
		if user.ID == "employee" {
			employeeAccountFound = user.Name == "Employee" && user.Email == "employee@example.com"
		}
	}
	for _, assignment := range seed.WorkforceAssignments {
		if assignment.WorkforceProfileID == "employee_workforce" {
			employeeWorkforceFound = assignment.OrganizationUnitID == "people" && assignment.ManagerWorkforceProfileID == "manager_workforce"
		}
	}
	if !employeeAccountFound || !employeeWorkforceFound {
		t.Fatalf("bootstrap account/workforce split is wrong: users=%#v workforce=%#v", seed.Users, seed.WorkforceAssignments)
	}
}

func TestManifestIdentitySeedDoesNotInferPlatformMenusFromBusinessPermissions(t *testing.T) {
	manifest := manifestmodel.ManifestSchema{
		Roles: []identitymodel.RoleSchema{
			{Key: "ceo", Name: "CEO", Permissions: []string{"identity.users.read", "workflow.definition.read", "leave_request.read"}},
			{Key: "hr_manager", Name: "HR Manager", Permissions: []string{"leave_request.read"}},
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

func TestManifestIdentitySeedAssignsPlatformMenusToWorkspaceAdministrator(t *testing.T) {
	manifest := manifestmodel.ManifestSchema{
		Roles: []identitymodel.RoleSchema{
			{Key: "runtime_admin", Name: "Runtime Administrator", Permissions: []string{" workspace.ADMIN "}},
			{Key: "business_manager", Name: "Business Manager", Permissions: []string{"identity.users.read"}},
		},
	}

	seed := FromManifest(manifest)
	assignments := map[string]bool{}
	for _, assignment := range seed.RoleMenus {
		assignments[assignment.RoleID+":"+assignment.MenuID] = true
	}
	if !assignments["runtime_admin:org_users"] || !assignments["runtime_admin:system_metadata"] {
		t.Fatalf("workspace administrator did not receive platform menus: %#v", seed.RoleMenus)
	}
	if assignments["business_manager:org_users"] {
		t.Fatalf("ordinary business permission expanded platform menu ownership: %#v", seed.RoleMenus)
	}
}

func TestGeneratedIdentityMenusDoNotPublishBusinessDataOperationsInTenantAdmin(t *testing.T) {
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
