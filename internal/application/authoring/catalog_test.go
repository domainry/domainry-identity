package authoring

import (
	"slices"
	"testing"

	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
)

func testAuthoringCatalog(t *testing.T) *AuthoringCatalog {
	t.Helper()
	registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	projection, err := registry.ProjectAuthoringDomain(identitycontract.IdentityAuthoringDomain())
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewAuthoringCatalog(projection.Domain())
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestCatalogContainsOnlyIdentityAdminCapabilities(t *testing.T) {
	catalog := testAuthoringCatalog(t)
	contract := catalog.Contract(Instance{SchemaHash: "schema", ObjectKeys: []string{"employee"}})

	if len(contract.Domains) != 1 || contract.Domains[0].Key != "identity" {
		t.Fatalf("domains = %#v", contract.Domains)
	}
	want := map[string]bool{
		"identity.organization_unit": true, "identity.menu": true, "identity.role": true,
		"identity.role_field_permission": true,
		"identity.role_permission":       true, "identity.user": true,
		"identity.user_role_assignment": true, "identity.role_menu_assignment": true,
		"identity.profile_binding": true,
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

func TestCatalogDerivesExactPermissionsFromActionProjection(t *testing.T) {
	catalog := testAuthoringCatalog(t)
	registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]Definition{}
	for _, definition := range catalog.Definitions() {
		byKey[definition.Key] = definition
	}
	if got := byKey["identity.user"].Permissions; !slices.Equal(got, []string{
		"identity.users.create", "identity.users.delete", "identity.users.disable", "identity.users.enable",
		"identity.users.get", "identity.users.update", "identity.users.validate", "identity.users.versions",
	}) {
		t.Fatalf("identity.user permissions=%v", got)
	}
	for _, definition := range catalog.Definitions() {
		for _, permission := range definition.Permissions {
			action, found := registry.Definition(permission)
			if !found || action.Permission == nil || action.Permission.Key != permission {
				t.Fatalf("capability %q retained permission outside canonical Action registry: %q", definition.Key, permission)
			}
		}
	}
}
