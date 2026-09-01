package identitymodel

import "testing"

func TestIdentityExpandRoleAuthorizationBlankAndMissingKeys(t *testing.T) {
	roles := []RoleSchema{{
		Permissions:         []string{"role.read"},
		PermissionSetKeys:   []string{" ", "direct"},
		PermissionSetGroups: []string{"group", "missing"},
		GuardrailKeys:       []string{"guard", "missing"},
	}}
	sets := []IdentityPermissionSet{{Key: " "}, {Key: "direct", DataPermissions: []DataPermission{{ObjectKey: "direct", Scope: "all_records", Read: true}}}, {Key: "grouped", FieldPermissions: []FieldPermission{{ObjectKey: "grouped", FieldKey: "name", Read: true}}}}
	groups := []IdentityPermissionSetGroup{{Key: " "}, {Key: "group", PermissionSetKeys: []string{" ", "grouped"}}}
	guardrails := []IdentityGuardrailPolicy{{Key: " "}, {Key: "guard"}, {Key: "second"}}
	roles[0].GuardrailKeys = []string{"second", "guard", "missing"}
	got := IdentityExpandRoleAuthorization(roles, sets, groups, guardrails)
	if len(got) != 1 || len(got[0].Permissions) != 1 || got[0].Permissions[0] != "role.read" || len(got[0].DataPermissions) != 1 || len(got[0].FieldPermissions) != 1 || len(got[0].Guardrails) != 2 {
		t.Fatalf("expanded=%#v", got)
	}
}
