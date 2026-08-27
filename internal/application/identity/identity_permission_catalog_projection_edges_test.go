package identity

import (
	"strings"
	"testing"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityPermissionProjectionEdges(t *testing.T) {
	objects := []definitionmodel.ObjectSchema{{Key: "order", Name: "Sales Order"}, {Key: "order", Name: "Duplicate"}, {Key: "blank_name"}, {Key: ""}, {Key: "system", Config: map[string]any{"system_object": true}}, {Key: "not_system", Config: map[string]any{"system_object": false}}}
	roles := []identitymodel.RoleSchema{{Permissions: []string{"", "workspace.admin", "order.read", "custom.action", "sales.order.approve.final", "identity_user.read", "identity_user"}}}
	permissions := IdentityPermissionsFromRoles(roles, objects, "en-US")
	keys := map[string]identitymodel.IdentityPermissionDefinition{}
	for _, permission := range permissions {
		keys[permission.Key] = permission
	}
	for _, key := range []string{"workspace.admin", "identity.permission.configure", "order.create", "order.read", "blank_name.delete", "not_system.update", "custom.action", "sales.order.approve.final", "identity_user.read", "identity_user"} {
		if _, ok := keys[key]; !ok {
			t.Errorf("missing %q", key)
		}
	}
	if _, ok := keys["system.read"]; ok {
		t.Fatal("system object permission emitted")
	}
	if keys["identity_user.read"].System != "domain" || keys["custom.action"].System != "domain" {
		t.Fatalf("unexpected definitions: %#v", keys)
	}
}

func TestIdentityPermissionProjectionSkipsBlankActionPermission(t *testing.T) {
	permissions := IdentityPermissionsFromRuntime(nil, nil, []definitionmodel.ActionSchema{{Key: "blank", RequiresPermission: " "}}, "en-US")
	if len(permissions) != 5 {
		t.Fatalf("permissions=%#v", permissions)
	}
}

func TestPlatformPermissionDefinitionBranches(t *testing.T) {
	objects := []definitionmodel.ObjectSchema{{Key: "order", Name: "Sales Order"}, {Key: "empty"}}
	cases := []struct {
		key  string
		want bool
	}{
		{"workspace.admin", true}, {"identity.permission.configure", true}, {"identity_user.read", true}, {"identity_user", false}, {"platform.identity.inspect.more", true}, {"platform.short", false}, {"order.read", false},
	}
	for _, tc := range cases {
		permission, ok := platformIdentityPermissionDefinition("en-US", objects, tc.key)
		if ok != tc.want {
			t.Errorf("%q ok=%v, want %v", tc.key, ok, tc.want)
		}
		if ok && (permission.Key != tc.key || permission.Label == "" || permission.Category == "") {
			t.Errorf("incomplete permission for %q: %#v", tc.key, permission)
		}
	}
}

func TestIdentityPermissionLabelHelpers(t *testing.T) {
	objects := []definitionmodel.ObjectSchema{{Key: "order", Name: "Sales Order"}, {Key: "blank"}}
	for _, test := range []struct{ key, system, resource, action string }{{"", "domain", "", ""}, {"order", "domain", "order", ""}, {"order.read", "domain", "order", "read"}, {"sales.order.approve.final", "sales", "order", "approve.final"}} {
		system, resource, action := IdentityParsePermissionKey(test.key)
		if system != test.system || resource != test.resource || action != test.action {
			t.Errorf("parse %q = %q/%q/%q", test.key, system, resource, action)
		}
	}
	if identityPlatformPermissionLabel("en-US", "") != "" || identityPlatformPermissionLabel("en-US", "missing.key") != "" || identityPlatformPermissionLabel("en-US", "workspace.admin") == "" {
		t.Fatal("platform label outcomes mismatch")
	}
	for _, resource := range []string{"", "workspace", "order", "blank", "unknown"} {
		got := identityPlatformPermissionResourceLabel("en-US", objects, resource)
		if (resource == "" && got != "") || (resource != "" && got == "") {
			t.Errorf("resource %q label = %q", resource, got)
		}
	}
	for _, locale := range []string{"en-US", "zh-CN"} {
		for _, resource := range []string{"", "order", "blank", "identity_user", "unknown"} {
			_ = identityPermissionResourceLabel(locale, objects, resource)
		}
		for _, action := range []string{"", "read", "approve.final", "unknown_action"} {
			_ = identityPermissionActionLabel(locale, action)
		}
		for _, system := range []string{"platform", "workspace", "identity", "domain", "sales", ""} {
			_ = identityPermissionSystemLabel(locale, system)
			_ = identityPermissionCategoryLabel(locale, system, "Resource")
		}
	}
	if identityPermissionCategoryLabel("en-US", "sales", "") == "" {
		t.Fatal("business category fallback blank")
	}
	for _, key := range []string{"identity_data_scope_policy", "identity_field_permission", "identity_permission", "identity_role", "identity_role_permission_assignment", "identity_user_role_assignment", "identity_user", "identity_department", "other"} {
		if localizedIdentityFallbackLabel("zh-CN", key, "Fallback") == "" || localizedIdentityFallbackLabel("en-US", key, "Fallback") != "Fallback" {
			t.Errorf("localized fallback mismatch for %q", key)
		}
	}
	if i18nLookup("unsupported", "anything") != "" || i18nLookup("en-US", "missing.key") != "" || i18nLookup("en-US", "action.read") == "" {
		t.Fatal("i18n lookup outcomes mismatch")
	}
	for _, value := range []string{"", " sales_order.item-name ", "plain"} {
		got := IdentityHumanizeIdentifier(value)
		if (value == "" && got != "") || (value != "" && strings.TrimSpace(got) == "") {
			t.Errorf("humanize %q = %q", value, got)
		}
	}
	if identityProjectionValueOrDefault(" value ", "fallback") != "value" || identityProjectionValueOrDefault(" ", "fallback") != "fallback" {
		t.Fatal("value fallback mismatch")
	}
	if got := nonEmptyStrings("", " a ", " ", "b"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("non-empty strings = %#v", got)
	}
	if !objectIsSystemOwned(definitionmodel.ObjectSchema{Config: map[string]any{"system_object": true}}) || objectIsSystemOwned(definitionmodel.ObjectSchema{Config: map[string]any{"system_object": false}}) || objectIsSystemOwned(definitionmodel.ObjectSchema{}) {
		t.Fatal("system ownership mismatch")
	}
}

func TestIdentityI18nCandidateOrdering(t *testing.T) {
	original := identityLocalizationLookup
	t.Cleanup(func() { identityLocalizationLookup = original })
	for _, target := range []string{"permission.resource.target", "object.target", "menu.target", "module.target", "system.target", "permission.runtime_inspect"} {
		identityLocalizationLookup = func(locale, key string) (string, bool) {
			if key == target {
				return " Label ", true
			}
			return "", false
		}
		var got string
		switch {
		case strings.HasPrefix(target, "system."):
			got = identityPermissionSystemLabel("en-US", "target")
		case strings.HasPrefix(target, "permission.runtime"):
			got = identityPlatformPermissionLabel("en-US", "platform.runtime-inspect")
		default:
			got = identityPermissionResourceLabel("en-US", nil, "target")
		}
		if got != " Label " {
			t.Errorf("target %q resolved to %q", target, got)
		}
	}
	identityLocalizationLookup = func(locale, key string) (string, bool) { return " ", true }
	if i18nLookup("en-US", "blank") != "" {
		t.Fatal("blank localized value accepted")
	}
}
