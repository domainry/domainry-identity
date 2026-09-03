package identitymodel

import (
	"sort"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

// IdentityDataScopeFilter is the internal, storage-facing projection of one
// exact Permission's data scopes. It is not an authoring enum and is never
// accepted from an HTTP request. Unrestricted means canonical `all`, for
// which repositories add no data-scope predicate.
type IdentityDataScopeFilter struct {
	Unrestricted bool
	OwnerUserIDs []string
	OwnerOrgIDs  []string
}

func (filter IdentityDataScopeFilter) Denied() bool {
	return !filter.Unrestricted && len(filter.OwnerUserIDs) == 0 && len(filter.OwnerOrgIDs) == 0
}

func (filter IdentityDataScopeFilter) Normalized() IdentityDataScopeFilter {
	if filter.Unrestricted {
		return IdentityDataScopeFilter{Unrestricted: true}
	}
	filter.OwnerUserIDs = normalizedIdentityScopeIDs(filter.OwnerUserIDs)
	filter.OwnerOrgIDs = normalizedIdentityScopeIDs(filter.OwnerOrgIDs)
	return filter
}

func normalizedIdentityScopeIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

const (
	IdentityDataScopeAll       = identitysdk.DataScopeAll
	IdentityDataScopeOwner     = identitysdk.DataScopeOwner
	IdentityDataScopeOrg       = identitysdk.DataScopeOrg
	IdentityDataScopeOrgChild  = identitysdk.DataScopeOrgChild
	IdentityDataScopeTargetOrg = identitysdk.DataScopeTargetOrg
)

func IdentityDataScopeValues() []IdentityDataScope {
	return identitysdk.DataScopeValues()
}

// AuthoringDataScopeValues is the only builder/runtime contract for role
// data-scope authoring and evaluation.
func AuthoringDataScopeValues() []string {
	values := identitysdk.DataScopeValues()
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func CanonicalIdentityDataScope(value string) (IdentityDataScope, bool) {
	scope := identitysdk.DataScope(value)
	if !scope.Valid() {
		return "", false
	}
	return scope, true
}

// RolePermissionsWithScope builds exact grants for trusted code and tests.
// Authoring boundaries still validate every supplied scope explicitly.
func RolePermissionsWithScope(scope IdentityDataScope, keys ...string) []RolePermission {
	permissions := make([]RolePermission, 0, len(keys))
	for _, key := range keys {
		if key = strings.TrimSpace(key); key != "" {
			permissions = append(permissions, RolePermission{PermissionKey: key, DataScope: scope})
		}
	}
	return permissions
}

func RolePermissionKeys(values []RolePermission) []string {
	keys := make([]string, 0, len(values))
	for _, value := range values {
		if key := strings.TrimSpace(value.PermissionKey); key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func NormalizeRolePermissions(values []RolePermission) ([]RolePermission, bool) {
	byKey := make(map[string]RolePermission, len(values))
	for _, value := range values {
		key := strings.TrimSpace(value.PermissionKey)
		scope, valid := CanonicalIdentityDataScope(strings.TrimSpace(string(value.DataScope)))
		if key == "" || !valid {
			return nil, false
		}
		if _, duplicate := byKey[key]; duplicate {
			return nil, false
		}
		value.PermissionKey = key
		value.DataScope = scope
		byKey[key] = value
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]RolePermission, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out, true
}

func RolePermissionForKey(values []RolePermission, key string) (RolePermission, bool) {
	key = strings.TrimSpace(key)
	for _, value := range values {
		if strings.TrimSpace(value.PermissionKey) == key && value.DataScope.Valid() {
			return value, true
		}
	}
	return RolePermission{}, false
}

// RolePermissionsForKey returns every effective grant for an exact Permission
// key. A published role contains at most one grant per key, while an effective
// principal may contain several because independently assigned roles can grant
// the same Permission with different data scopes.
func RolePermissionsForKey(values []RolePermission, key string) []RolePermission {
	key = strings.TrimSpace(key)
	result := make([]RolePermission, 0, 1)
	for _, value := range values {
		if strings.TrimSpace(value.PermissionKey) == key && value.DataScope.Valid() {
			result = append(result, value)
		}
	}
	return result
}

// RolePermissionResource returns the resource portion of an exact Permission
// key. Permission actions are the final dot-separated segment.
func RolePermissionResource(permissionKey string) string {
	permissionKey = strings.TrimSpace(permissionKey)
	separator := strings.LastIndex(permissionKey, ".")
	if separator <= 0 || separator == len(permissionKey)-1 {
		return ""
	}
	return permissionKey[:separator]
}
