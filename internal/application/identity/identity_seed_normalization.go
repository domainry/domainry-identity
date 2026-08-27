package identity

import (
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func MergeIdentityPermissions(seed []identitymodel.IdentityPermissionDefinition, fallback []identitymodel.IdentityPermissionDefinition) []identitymodel.IdentityPermissionDefinition {
	byKey := map[string]identitymodel.IdentityPermissionDefinition{}
	for _, permission := range fallback {
		if strings.TrimSpace(permission.Key) != "" {
			byKey[permission.Key] = permission
		}
	}
	for _, permission := range seed {
		if strings.TrimSpace(permission.Key) != "" {
			byKey[permission.Key] = permission
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]identitymodel.IdentityPermissionDefinition, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key, ok := range values {
		if ok && strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func sortedDataScopes(values map[string]identitymodel.IdentityDataScopePolicy) []identitymodel.IdentityDataScopePolicy {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]identitymodel.IdentityDataScopePolicy, 0, len(keys))
	for _, key := range keys {
		out = append(out, values[key])
	}
	return out
}

func sortedFieldPermissions(values map[string]identitymodel.IdentityFieldPermission) []identitymodel.IdentityFieldPermission {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]identitymodel.IdentityFieldPermission, 0, len(keys))
	for _, key := range keys {
		out = append(out, values[key])
	}
	return out
}
