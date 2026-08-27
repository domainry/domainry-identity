package identitymodel

import "testing"

func TestIdentityExpandRoleAuthorizationBlankAndMissingKeys(t *testing.T) {
	roles := []RoleSchema{{
		PermissionSetKeys:   []string{" ", "direct"},
		PermissionSetGroups: []string{"group", "missing"},
		GuardrailKeys:       []string{"guard", "missing"},
	}}
	sets := []IdentityPermissionSet{{Key: " "}, {Key: "direct", Permissions: []string{"direct.read"}}, {Key: "grouped", Permissions: []string{"group.read"}}}
	groups := []IdentityPermissionSetGroup{{Key: " "}, {Key: "group", PermissionSetKeys: []string{" ", "grouped"}}}
	guardrails := []IdentityGuardrailPolicy{{Key: " "}, {Key: "guard"}, {Key: "second"}}
	roles[0].GuardrailKeys = []string{"second", "guard", "missing"}
	got := IdentityExpandRoleAuthorization(roles, sets, groups, guardrails)
	if len(got) != 1 || len(got[0].Permissions) != 2 || len(got[0].Guardrails) != 2 {
		t.Fatalf("expanded=%#v", got)
	}
}
