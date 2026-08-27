package authoring

import "testing"

func TestCatalogContainsOnlyIdentityAdminCapabilities(t *testing.T) {
	catalog := NewAuthoringCatalog()
	contract := catalog.Contract(Instance{SchemaHash: "schema", ObjectKeys: []string{"employee"}})

	if len(contract.Domains) != 2 || contract.Domains[0].Key != "identity" || contract.Domains[1].Key != "schema" {
		t.Fatalf("domains = %#v", contract.Domains)
	}
	want := map[string]bool{
		"identity.department": true, "identity.menu": true, "identity.role": true,
		"identity.role_data_scope": true, "identity.role_field_permission": true,
		"identity.role_permission": true, "identity.user": true,
		"identity.user_role_assignment": true, "schema.field": true, "schema.relation": true,
	}
	for _, definition := range catalog.Definitions() {
		if !want[definition.Key] {
			t.Fatalf("unexpected capability %#v", definition)
		}
		delete(want, definition.Key)
	}
	if len(want) != 0 {
		t.Fatalf("missing capabilities = %#v", want)
	}
	if contract.ContractHash == "" || contract.InstanceHash == "" {
		t.Fatalf("hashes = %#v", contract)
	}
}

func TestCatalogPublishesFieldAndDataScopeEnums(t *testing.T) {
	catalog := NewAuthoringCatalog()
	parameters := map[string]Parameter{}
	for _, definition := range catalog.Definitions() {
		for _, parameter := range definition.Parameters {
			parameters[definition.Key+"."+parameter.Key] = parameter
		}
	}
	if got := parameters["schema.field.type"].Enum; len(got) == 0 || got[0] != "boolean" {
		t.Fatalf("field type enum = %#v", got)
	}
	if got := parameters["identity.role_data_scope.data_scope"].Enum; len(got) != 8 {
		t.Fatalf("data scope enum = %#v", got)
	}
}
