package contract

import (
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// IdentityRoleHasPermissionKey reports whether a role grants the exact
// Permission key. Action authorization never expands one exact grant or a
// wildcard into another Action key.
func IdentityRoleHasPermissionKey(role identitymodel.RoleSchema, key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	if IdentityRoleGuardrailDeniesPermission(role, key) {
		return false
	}
	for _, permission := range role.Permissions {
		if strings.TrimSpace(permission.PermissionKey) == key && permission.Valid() {
			return true
		}
	}
	return false
}

// IdentityRoleAllows reports whether a role grants an action on an object.
func IdentityRoleAllows(role identitymodel.RoleSchema, objectKey, action string) bool {
	action = identityNormalizePermissionAction(action)
	return IdentityRoleHasPermissionKey(role, strings.TrimSpace(objectKey)+"."+action)
}

// IdentityRoleAllowsData reports whether the exact requested Permission grant
// carries a valid data scope.
func IdentityRoleAllowsData(role identitymodel.RoleSchema, resource, action string) bool {
	if IdentityRoleGuardrailDeniesData(role, resource, action) {
		return false
	}
	return len(identitymodel.RolePermissionsForKey(role.Permissions, strings.TrimSpace(resource)+"."+identityNormalizePermissionAction(action))) != 0
}

// IdentityRoleGuardrailDeniesPermission reports whether any effective
// deny-only guardrail matches an exact or wildcard permission key.
func IdentityRoleGuardrailDeniesPermission(role identitymodel.RoleSchema, key string) bool {
	key = strings.TrimSpace(key)
	for _, guardrail := range role.Guardrails {
		for _, denied := range guardrail.DeniedPermissionKeys {
			denied = strings.TrimSpace(denied)
			if denied == "*" || denied == key || strings.HasSuffix(denied, ".*") && strings.HasPrefix(key, strings.TrimSuffix(denied, ".*")+".") {
				return true
			}
		}
	}
	return false
}

func IdentityRoleGuardrailDeniesData(role identitymodel.RoleSchema, objectKey, action string) bool {
	action = identityNormalizePermissionAction(action)
	for _, guardrail := range role.Guardrails {
		for _, restriction := range guardrail.DataRestrictions {
			if strings.TrimSpace(restriction.ObjectKey) == strings.TrimSpace(objectKey) && identityGuardrailActionMatches(restriction.Actions, action) {
				return true
			}
		}
	}
	return false
}

func IdentityRoleGuardrailDeniesField(role identitymodel.RoleSchema, objectKey, fieldKey, action string) bool {
	action = identityNormalizePermissionAction(action)
	for _, guardrail := range role.Guardrails {
		for _, restriction := range guardrail.FieldRestrictions {
			if strings.TrimSpace(restriction.ObjectKey) == strings.TrimSpace(objectKey) &&
				strings.TrimSpace(restriction.FieldKey) == strings.TrimSpace(fieldKey) &&
				identityGuardrailActionMatches(restriction.Actions, action) {
				return true
			}
		}
	}
	return false
}

func identityGuardrailActionMatches(actions []string, action string) bool {
	for _, candidate := range actions {
		candidate = identityNormalizePermissionAction(candidate)
		if candidate == "*" || candidate == action {
			return true
		}
	}
	return false
}

// IdentityDataScopesForAction returns the scope carried by the exact Permission
// grant. An empty result means deny.
func IdentityDataScopesForAction(role identitymodel.RoleSchema, resource, action string) []identitymodel.IdentityDataScope {
	if IdentityRoleGuardrailDeniesData(role, resource, action) {
		return nil
	}
	permissions := identitymodel.RolePermissionsForKey(role.Permissions, strings.TrimSpace(resource)+"."+identityNormalizePermissionAction(action))
	if len(permissions) == 0 {
		return nil
	}
	seen := map[identitymodel.IdentityDataScope]bool{}
	result := make([]identitymodel.IdentityDataScope, 0, len(permissions))
	for _, permission := range permissions {
		if !seen[permission.DataScope] {
			seen[permission.DataScope] = true
			result = append(result, permission.DataScope)
		}
	}
	return result
}

func identityNormalizePermissionAction(action string) string {
	return strings.TrimSpace(action)
}
