package identity

import (
	"os"
	"strings"
	"testing"
)

func TestIdentityManagementRoutesRegisterExactActionsWithoutLegacyPermissionWrappers(t *testing.T) {
	raw, err := os.ReadFile("identity_routes.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, forbidden := range []string{"h.Admin(", "identityPermission(", "identityPermissions(", "identityPermissionOrSelf(", "h.Authenticated("} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("identity management routes still use legacy wrapper %q", forbidden)
		}
	}
	for _, required := range []string{
		`"identity.workforce.list"`,
		`"identity.workforce.lifecycle"`,
		`"identity.roles.list"`,
		`"identity.role_permissions.publish"`,
		`"identity.users.force_logout"`,
		`"identity.profile_bindings.command"`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("identity management routes do not register exact Action %s", required)
		}
	}
	if strings.Count(source, "registerIdentityAction(") < 80 {
		t.Fatalf("identity route matrix is unexpectedly incomplete: registrations=%d", strings.Count(source, "registerIdentityAction("))
	}
}
