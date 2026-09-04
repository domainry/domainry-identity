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

func TestAuthProviderAllowedPurposesAreTypedAndDefaultBackwardCompatible(t *testing.T) {
	legacy := AuthProviderConfigFromMap(map[string]any{"key": "sms", "type": "otp"})
	if !legacy.SupportsChallengePurpose(AuthChallengePurposeLogin) || !legacy.SupportsChallengePurpose(AuthChallengePurposeLoginMFA) || !legacy.SupportsChallengePurpose(AuthChallengePurposeAction) {
		t.Fatalf("legacy OTP purposes=%#v", legacy.AllowedPurposes)
	}
	actionOnly := AuthProviderConfigFromMap(map[string]any{"key": "sms", "type": "otp", "allowed_purposes": []any{AuthChallengePurposeAction}})
	if actionOnly.SupportsChallengePurpose(AuthChallengePurposeLogin) || actionOnly.SupportsChallengePurpose(AuthChallengePurposeLoginMFA) || !actionOnly.SupportsChallengePurpose(AuthChallengePurposeAction) {
		t.Fatalf("action-only OTP purposes=%#v", actionOnly.AllowedPurposes)
	}
	if safe := actionOnly.SafeMap(); !reflect.DeepEqual(safe["allowed_purposes"], []string{AuthChallengePurposeAction}) {
		t.Fatalf("safe purposes=%#v", safe)
	}
	for _, values := range [][]string{{}, {"unknown"}, {AuthChallengePurposeAction, AuthChallengePurposeAction}} {
		if _, err := NormalizeAuthProviderAllowedPurposes(values); err == nil {
			t.Fatalf("invalid purposes accepted: %#v", values)
		}
	}
}
