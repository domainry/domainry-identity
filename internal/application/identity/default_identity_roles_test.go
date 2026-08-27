package identity

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestWithStandaloneIdentityRoleDefinitionsProvidesAdminAuthorityAndHonorsOverrides(t *testing.T) {
	roles := WithStandaloneIdentityRoleDefinitions([]identitymodel.RoleSchema{{Key: "admin", Name: "Configured admin", Permissions: []string{"custom.admin"}}})
	byKey := map[string]identitymodel.RoleSchema{}
	for _, role := range roles {
		byKey[role.Key] = role
	}
	if len(byKey) != 3 {
		t.Fatalf("role count = %d, want 3", len(byKey))
	}
	if got := byKey["admin"]; got.Name != "Configured admin" || len(got.Permissions) != 1 || got.Permissions[0] != "custom.admin" {
		t.Fatalf("configured admin override = %#v", got)
	}
	organization := byKey["organization_administrator"]
	for _, expected := range []string{"identity.users.read", "identity.roles.write", "audit.governance.read", "metadata.write"} {
		found := false
		for _, permission := range organization.Permissions {
			found = found || permission == expected
		}
		if !found {
			t.Fatalf("organization administrator missing %s", expected)
		}
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
