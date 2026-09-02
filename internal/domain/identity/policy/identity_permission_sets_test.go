package policy

import (
	"reflect"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestExpandRolePermissionSetsComposesGroupsDeterministically(t *testing.T) {
	sets := []identitymodel.IdentityPermissionSet{
		{Key: "case_read", DataPermissions: []identitymodel.DataPermission{{ObjectKey: "case", Scope: "owned_records"}}},
		{
			Key:              "case_department",
			DataPermissions:  []identitymodel.DataPermission{{ObjectKey: "case", Scope: "organization"}},
			FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "case", FieldKey: "amount", Read: true}},
			ReferencePermissions: []identitymodel.ReferencePermission{{
				SourceObjectKey: "case", RelationFieldKey: "customer_id", TargetObjectKey: "customer", DisplayFields: []string{"name"},
			}},
			ExportRules: []identitymodel.ExportRule{{ObjectKey: "case", Mode: "allow_list", Fields: []string{"id", "amount"}}},
		},
	}
	groups := []identitymodel.IdentityPermissionSetGroup{{Key: "case_operator", PermissionSetKeys: []string{"case_department", "case_read"}}}
	roles := []identitymodel.RoleSchema{{Key: "operator", Permissions: []string{"case.resolve"}, PermissionSetKeys: []string{"case_read"}, PermissionSetGroups: []string{"case_operator"}}}
	first := ExpandRolePermissionSets(roles, sets, groups)
	second := ExpandRolePermissionSets(roles, []identitymodel.IdentityPermissionSet{sets[1], sets[0]}, groups)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("set order changed expansion:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if len(first) != 1 ||
		!reflect.DeepEqual(first[0].Permissions, []string{"case.resolve"}) ||
		len(first[0].DataPermissions) != 2 ||
		len(first[0].FieldPermissions) != 1 ||
		len(first[0].ReferencePermissions) != 1 ||
		len(first[0].ExportRules) != 1 {
		t.Fatalf("expanded roles=%#v", first)
	}
}

func TestExpandRolePermissionSetsIgnoresUnknownReferencesWithoutAddingAuthority(t *testing.T) {
	roles := ExpandRolePermissionSets(
		[]identitymodel.RoleSchema{{Key: "operator", PermissionSetKeys: []string{"missing"}, PermissionSetGroups: []string{"missing"}}},
		nil,
		nil,
	)
	if len(roles) != 1 || len(roles[0].Permissions) != 0 || len(roles[0].DataPermissions) != 0 {
		t.Fatalf("unknown reference added authority: %#v", roles)
	}
}

func TestExpandRoleAuthorizationAttachesReusableGuardrail(t *testing.T) {
	guardrail := identitymodel.IdentityGuardrailPolicy{Key: "no_export", DeniedPermissionKeys: []string{"case.export"}}
	roles := ExpandRoleAuthorization(
		[]identitymodel.RoleSchema{{Key: "operator", Permissions: []string{"case.export"}, GuardrailKeys: []string{"no_export"}}},
		nil,
		nil,
		[]identitymodel.IdentityGuardrailPolicy{guardrail},
	)
	if len(roles) != 1 || len(roles[0].Guardrails) != 1 || roles[0].Guardrails[0].Key != "no_export" {
		t.Fatalf("roles=%#v", roles)
	}
}
