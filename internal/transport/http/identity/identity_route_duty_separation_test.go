package identity

import (
	"os"
	"strings"
	"testing"
)

func TestIdentityManagementRoutesUseDutySpecificPermissions(t *testing.T) {
	raw, err := os.ReadFile("identity_routes.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	if strings.Contains(source, "h.Admin(") {
		t.Fatal("identity management routes still use the workspace-wide admin gate")
	}
	for _, required := range []string{
		`"identity.workforce.read"`,
		`"identity.workforce.write"`,
		`"identity.roles.read"`,
		`"identity.roles.write"`,
		`"identity.security.write"`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("identity management routes do not publish duty permission %s", required)
		}
	}
	if !strings.Contains(source, `identityPermissions([]string{"identity.users.write", "identity.roles.write"}`) {
		t.Fatal("mixed account-and-role command does not require both duties")
	}
	profileRaw, err := os.ReadFile("../../../application/identity/identity_profile_binding_application_service.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profileRaw), `"identity.profile_binding.manage"`) {
		t.Fatal("business-profile operations do not enforce the member-operations duty")
	}
}
