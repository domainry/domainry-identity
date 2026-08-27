package authmodel

import (
	"reflect"
	"testing"
)

func TestAuthProviderRoleMappingsAcceptTypedMapsAndIgnoreInvalidAnyItems(t *testing.T) {
	typed := authProviderRoleMappingsFromAny([]map[string]string{{"claim": "group", "match": "admin", "role_key": "owner"}})
	want := []AuthExternalRoleMapping{{Claim: "group", Match: "admin", RoleKey: "owner"}}
	if !reflect.DeepEqual(typed, want) {
		t.Fatalf("typed mappings=%#v", typed)
	}
	mixed := authProviderRoleMappingsFromAny([]any{
		"invalid",
		map[string]any{"claim": " group ", "match": " admin ", "role_key": " owner "},
	})
	if !reflect.DeepEqual(mixed, want) {
		t.Fatalf("mixed mappings=%#v", mixed)
	}
}
