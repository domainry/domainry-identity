package contract

import (
	"reflect"
	"sort"
	"testing"

	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
)

func TestIdentityUserAuthoringContractContainsOnlyAccountFields(t *testing.T) {
	definition := IdentityUserAuthoringCapability()
	wantInput := []string{"account_type", "email", "family_name", "given_name", "id", "locale", "middle_name", "name", "name_locale", "name_prefix", "name_suffix", "native_name", "phone", "status", "timezone"}
	wantOutput := append(append([]string(nil), wantInput...), "created_at", "updated_at", "version")
	sort.Strings(wantOutput)
	for label, expectation := range map[string]struct {
		schema *authoringcontract.CapabilityAuthoringSchema
		fields []string
	}{"input": {schema: definition.InputSchema, fields: wantInput}, "output": {schema: definition.OutputSchema, fields: wantOutput}} {
		keys := make([]string, 0, len(expectation.schema.Properties))
		for key := range expectation.schema.Properties {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if !reflect.DeepEqual(keys, expectation.fields) {
			t.Errorf("%s identity.user fields=%v want=%v", label, keys, expectation.fields)
		}
	}
	parameters := make([]string, 0, len(definition.Parameters))
	for _, parameter := range definition.Parameters {
		parameters = append(parameters, parameter.Key)
	}
	sort.Strings(parameters)
	if !reflect.DeepEqual(parameters, wantInput) {
		t.Errorf("identity.user parameters=%v want=%v", parameters, wantInput)
	}
}

func TestIdentityRoleAuthoringContractsPublishExactHTTPShapes(t *testing.T) {
	for _, capability := range []struct {
		definitionKey string
		inputRequired []string
		actual        func() string
	}{
		{definitionKey: "identity.role", inputRequired: []string{"id", "key", "label", "status"}, actual: func() string { return IdentityRoleAuthoringCapability().Key }},
		{definitionKey: "identity.role_permission", inputRequired: []string{"permission_keys"}, actual: func() string { return IdentityRolePermissionAuthoringCapability().Key }},
	} {
		if capability.actual() != capability.definitionKey {
			t.Fatalf("capability key=%s", capability.actual())
		}
	}
	role := IdentityRoleAuthoringCapability()
	if role.InputSchema == nil || role.InputSchema.AdditionalProperties == nil || *role.InputSchema.AdditionalProperties || len(role.Examples) != 3 {
		t.Fatalf("role=%#v", role)
	}
	rolePayload := role.InputSchema.Properties["payload"]
	for _, field := range []string{"permission_set_keys", "permission_set_group_keys", "guardrail_keys"} {
		if _, ok := rolePayload.Properties[field]; !ok {
			t.Fatalf("role authoring contract missing %s", field)
		}
	}
	permission := IdentityRolePermissionAuthoringCapability()
	if permission.InputSchema == nil || permission.OutputSchema == nil || len(permission.ReferenceContracts) != 2 || permission.ResourceOperations != nil || permission.Execution.ChangeControl != "reviewed_system_draft_change_plan" {
		t.Fatalf("permission=%#v", permission)
	}
	for _, capability := range []struct {
		key      string
		required string
		value    func() authoringcontract.CapabilityAuthoringDefinition
	}{
		{key: "identity.role_data_scope", required: "data_scopes", value: IdentityRoleDataScopeAuthoringCapability},
		{key: "identity.role_field_permission", required: "field_permissions", value: IdentityRoleFieldPermissionAuthoringCapability},
		{key: "identity.menu", required: "id", value: IdentityMenuAuthoringCapability},
		{key: "identity.role_menu_assignment", required: "menu_ids", value: IdentityRoleMenuAssignmentAuthoringCapability},
		{key: "identity.user", required: "email", value: IdentityUserAuthoringCapability},
		{key: "identity.department", required: "name", value: IdentityDepartmentAuthoringCapability},
		{key: "identity.user_role_assignment", required: "role_id", value: IdentityUserRoleAssignmentAuthoringCapability},
		{key: "identity.workforce_profile", required: "worker_no", value: IdentityWorkforceProfileAuthoringCapability},
		{key: "identity.workforce_assignment", required: "assignment_type", value: IdentityWorkforceAssignmentAuthoringCapability},
	} {
		definition := capability.value()
		if definition.Key != capability.key || definition.InputSchema == nil || definition.InputSchema.AdditionalProperties == nil || *definition.InputSchema.AdditionalProperties || len(definition.Examples) != 3 {
			t.Fatalf("owner capability %s=%#v", capability.key, definition)
		}
		if _, ok := definition.InputSchema.Properties[capability.required]; !ok {
			t.Fatalf("owner capability %s missing request field %s", capability.key, capability.required)
		}
		if capability.key == "identity.role_data_scope" || capability.key == "identity.role_field_permission" {
			if definition.ResourceOperations != nil || definition.Execution == nil || definition.Execution.ChangeControl != "reviewed_system_draft_change_plan" {
				t.Fatalf("role policy capability %s still publishes direct mutation: %#v", capability.key, definition)
			}
		}
	}
}
