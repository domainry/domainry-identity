package identity

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestWithStandaloneIdentityRoleDefinitionsProvidesAdminAuthorityAndHonorsOverrides(t *testing.T) {
	roles := WithStandaloneIdentityRoleDefinitions([]identitymodel.RoleSchema{{Key: "admin", Name: "Configured admin", Permissions: identityTestRolePermissions("custom.admin")}})
	byKey := map[string]identitymodel.RoleSchema{}
	for _, role := range roles {
		byKey[role.Key] = role
	}
	if len(byKey) != 3 {
		t.Fatalf("role count = %d, want 3", len(byKey))
	}
	if got := byKey["admin"]; got.Name != "Configured admin" || len(got.Permissions) != 1 || got.Permissions[0].PermissionKey != "custom.admin" {
		t.Fatalf("configured admin override = %#v", got)
	}
	organization := byKey["organization_administrator"]
	for _, expected := range []string{
		"identity.users.list",
		"identity.users.update",
		"identity.roles.list",
		"identity.role_permissions.publish",
	} {
		found := false
		for _, permission := range organization.Permissions {
			found = found || permission.PermissionKey == expected
		}
		if !found {
			t.Fatalf("organization administrator missing %s", expected)
		}
	}
	if system := byKey["system_administrator"]; len(system.Permissions) == 0 {
		t.Fatalf("system administrator has no explicitly owned system permissions: %#v", system)
	}
}

func TestGeneratedIdentityAdminSeedKeepsGovernanceAuditMenuAssigned(t *testing.T) {
	seed := generatedManifestIdentitySeed()
	menuFound := false
	assignmentFound := false
	for _, menu := range seed.Menus {
		menuFound = menuFound || menu.ID == "system_audit" && menu.Route == "/admin/system/audit"
	}
	for _, assignment := range seed.RoleMenus {
		assignmentFound = assignmentFound || assignment.RoleID == "admin" && assignment.MenuID == "system_audit"
	}
	if !menuFound || !assignmentFound {
		t.Fatalf("governance audit seed menu=%v assignment=%v", menuFound, assignmentFound)
	}
}

func TestGeneratedIdentityOrganizationAdministratorMenusMatchItsOwnedPermissions(t *testing.T) {
	seed := generatedManifestIdentitySeed()
	assigned := map[string]bool{}
	for _, assignment := range seed.RoleMenus {
		if assignment.RoleID == "organization_administrator" {
			assigned[assignment.MenuID] = true
		}
	}
	for _, expected := range []string{
		"org_access", "org_users", "org_organization_units", "org_roles",
		"org_access_governance", "org_field_permissions", "org_menus",
		"model_config", "system_metadata",
	} {
		if !assigned[expected] {
			t.Fatalf("organization administrator missing menu %q: %#v", expected, assigned)
		}
	}
	for _, forbidden := range []string{"data_compliance", "system_audit"} {
		if assigned[forbidden] {
			t.Fatalf("organization administrator received menu %q without its required Audit permission: %#v", forbidden, assigned)
		}
	}
}
