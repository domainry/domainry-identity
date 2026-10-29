package identity

import (
	"strings"
	"testing"
)

func TestIdentityBuiltinPermissionCopyDoesNotExposeHandlerImplementationTerm(t *testing.T) {
	for _, action := range IdentityBuiltinAuthorizationActions() {
		if action.Permission == nil {
			continue
		}
		localized := action.Permission.I18n["zh-CN"]
		values := map[string]string{
			"capability label": action.CapabilityLabel,
			"group label":      localized.GroupLabel,
			"resource label":   localized.ResourceLabel,
			"operation label":  localized.OperationLabel,
			"label":            localized.Label,
			"description":      localized.Description,
		}
		for field, value := range values {
			if strings.Contains(strings.ToLower(value), "handler") {
				t.Errorf("permission %q %s exposes implementation term Handler: %q", action.Permission.Key, field, value)
			}
		}
	}
}
