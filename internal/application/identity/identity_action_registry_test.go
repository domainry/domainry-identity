package identity

import (
	"slices"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestStandaloneAuthorizationSliceRegistryOwnsCompleteRouteAndPermissionMatrix(t *testing.T) {
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	wantRoutes := []string{
		"GET /identity/permissions",
		"GET /identity/roles",
		"GET /identity/roles/search",
		"GET /identity/roles/{roleID}",
		"GET /identity/roles/{roleID}/governance-detail",
		"GET /identity/roles/{roleID}/permissions",
		"GET /identity/roles/{roleID}/versions",
		"POST /identity/governance/validate",
		"POST /identity/roles/{roleID}/impact-preview",
		"POST /identity/roles/{roleID}/permissions/validate",
		"POST /identity/roles/{roleID}/validate",
		"PUT /identity/roles/{roleID}/permissions",
	}
	gotRoutes := []string{}
	for _, definition := range registry.Definitions() {
		gotRoutes = append(gotRoutes, definition.HTTP.Method+" "+definition.HTTP.RouteTemplate)
		if definition.Page == nil || definition.Page.Route != "/admin/org/roles" {
			t.Fatalf("action %q page binding=%+v", definition.Key, definition.Page)
		}
	}
	slices.Sort(gotRoutes)
	slices.Sort(wantRoutes)
	if !slices.Equal(gotRoutes, wantRoutes) {
		t.Fatalf("routes=%v want %v", gotRoutes, wantRoutes)
	}
	permissions := registry.OwnedPermissionDefinitions(IdentityBuiltinAuthorizationOwner)
	keys := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		keys = append(keys, permission.PermissionKey)
		if len(registry.PermissionUsages(permission.PermissionKey)) == 0 {
			t.Fatalf("permission %q has no live action usage", permission.PermissionKey)
		}
	}
	if want := []string{"identity.permissions.read", "identity.permissions.write", "identity.roles.read", "identity.roles.write"}; !slices.Equal(keys, want) {
		t.Fatalf("owned permissions=%v want %v", keys, want)
	}
}

func TestIdentityActionRegistryRejectsDuplicatePermissionOwnersAndUnknownReferences(t *testing.T) {
	action := StandaloneIdentityAuthorizationSliceActions()[0]
	duplicate := action
	duplicate.Key = "identity.roles.list_duplicate"
	duplicate.HTTP.RouteTemplate = "/identity/roles-duplicate"
	if _, err := NewIdentityActionRegistry([]identitymodel.IdentityActionDefinition{action, duplicate}); err == nil {
		t.Fatal("duplicate permission ownership accepted")
	}
	unknown := action
	unknown.RequiredPermissions = []string{"identity.unknown"}
	unknown.OwnedPermissions = nil
	if _, err := NewIdentityActionRegistry([]identitymodel.IdentityActionDefinition{unknown}); err == nil {
		t.Fatal("unknown permission reference accepted")
	}
}
