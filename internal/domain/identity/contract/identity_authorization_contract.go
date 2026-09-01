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
		permission = strings.TrimSpace(permission)
		if permission == key {
			return true
		}
	}
	return false
}

// IdentityRoleHasExactPermissionKey is retained for call sites that emphasize
// ops isolation; functional permission matching itself is always exact.
func IdentityRoleHasExactPermissionKey(role identitymodel.RoleSchema, key string) bool {
	return IdentityRoleHasPermissionKey(role, key)
}

// IdentityRoleAllows reports whether a role grants an action on an object.
func IdentityRoleAllows(role identitymodel.RoleSchema, objectKey, action string) bool {
	action = identityNormalizePermissionAction(action)
	return IdentityRoleHasPermissionKey(role, strings.TrimSpace(objectKey)+"."+action)
}

// IdentityRoleAllowsData reports whether data permissions grant the requested
// read/export or write action for an object.
func IdentityRoleAllowsData(role identitymodel.RoleSchema, objectKey, action string) bool {
	if IdentityRoleGuardrailDeniesData(role, objectKey, action) {
		return false
	}
	needsWrite := action != "read" && action != "export"
	for _, permission := range role.DataPermissions {
		if permission.ObjectKey != objectKey {
			continue
		}
		if needsWrite && permission.Write {
			return true
		}
		if !needsWrite && permission.Read {
			return true
		}
	}
	return false
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

// IdentityDataScopeForAction resolves the role's record scope for an action.
func IdentityDataScopeForAction(role identitymodel.RoleSchema, objectKey, action string) string {
	return IdentityDataScope(role, objectKey, action != "read" && action != "export")
}

// IdentityDataScope resolves a role's read or write scope for an object.
func IdentityDataScope(role identitymodel.RoleSchema, objectKey string, write bool) string {
	scopes := map[string]bool{}
	for _, permission := range role.DataPermissions {
		if permission.ObjectKey != objectKey {
			continue
		}
		if write && !permission.Write || !write && !permission.Read {
			continue
		}
		scope := strings.TrimSpace(permission.Scope)
		if scope == "" {
			scope = "none"
		}
		if scope == "all_records" {
			return scope
		}
		scopes[scope] = true
	}
	if len(scopes) == 1 {
		for scope := range scopes {
			return scope
		}
	}
	if len(scopes) > 1 {
		return "custom"
	}
	return "none"
}

func identityNormalizePermissionAction(action string) string {
	return strings.TrimSpace(action)
}
