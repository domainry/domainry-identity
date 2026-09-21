package identitymodel

import (
	"encoding/json"
	"strings"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

func TestCanonicalIdentityDataScope(t *testing.T) {
	tests := map[string]IdentityDataScope{"all": IdentityDataScopeAll, "owner": IdentityDataScopeOwner, "org": IdentityDataScopeOrg, "org_child": IdentityDataScopeOrgChild, "target_org": IdentityDataScopeTargetOrg}
	for input, want := range tests {
		if got, ok := CanonicalIdentityDataScope(input); !ok || got != want {
			t.Errorf("CanonicalIdentityDataScope(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
	for _, rejected := range []string{"all_records", "owned_records", "organization", "organization_and_children", "self_and_subordinates", "custom", "none", "owned", "team"} {
		if _, ok := CanonicalIdentityDataScope(rejected); ok {
			t.Fatalf("legacy or unknown scope %q accepted", rejected)
		}
	}
}

func TestNormalizeRolePermissionsAcceptsExactlyOneClosedRelationalPolicy(t *testing.T) {
	policy := identitysdk.ProjectDataPolicy{Operator: identitysdk.ProjectDataPolicyEq, FieldKey: "owner_id", SubjectClaim: identitysdk.ProjectSubjectClaimID}
	permissions, valid := NormalizeRolePermissions([]RolePermission{{PermissionKey: " order.read ", DataPolicy: &policy}})
	if !valid || len(permissions) != 1 || permissions[0].PermissionKey != "order.read" || permissions[0].DataScope != "" || permissions[0].DataPolicy == nil {
		t.Fatalf("normalized permissions=%#v valid=%t", permissions, valid)
	}
	policy.FieldKey = "mutated"
	if permissions[0].DataPolicy.FieldKey != "owner_id" {
		t.Fatal("normalized role permission retained an alias to the authoring request")
	}
	if _, valid := NormalizeRolePermissions([]RolePermission{{PermissionKey: "order.read", DataScope: IdentityDataScopeAll, DataPolicy: permissions[0].DataPolicy}}); valid {
		t.Fatal("data_scope plus data_policy was accepted")
	}
}

func TestRolePermissionOwnsOneExactPermissionAndDataScope(t *testing.T) {
	encoded, err := json.Marshal(RolePermission{PermissionKey: "customer.read", DataScope: IdentityDataScopeOwner})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"read"`) || strings.Contains(string(encoded), `"write"`) {
		t.Fatalf("data policy leaked functional authority: %s", encoded)
	}
	effective, err := json.Marshal(IdentityEffectiveDataAccess{Resource: "customer", Allowed: true, Scopes: []IdentityDataScope{IdentityDataScopeOwner}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(effective), `"predicate"`) || strings.Contains(string(effective), `"object_key"`) {
		t.Fatalf("effective data access leaked legacy policy fields: %s", effective)
	}
	if strings.Contains(string(encoded), `"object_key"`) || strings.Contains(string(encoded), `"predicate"`) || strings.Contains(string(encoded), `"resource"`) {
		t.Fatalf("role permission leaked legacy contract fields: %s", encoded)
	}
}
