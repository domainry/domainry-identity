package policy

import (
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// IdentityRoleHasPermissionKey reports whether a role grants an exact permission,
// the workspace administrator permission, or a matching wildcard permission.
func IdentityRoleHasPermissionKey(role identitymodel.RoleSchema, key string) bool {
	return identitycontract.IdentityRoleHasPermissionKey(role, key)
}

func IdentityRoleHasExactPermissionKey(role identitymodel.RoleSchema, key string) bool {
	return identitycontract.IdentityRoleHasExactPermissionKey(role, key)
}

// IdentityRoleAllows reports whether a role grants an action on an object.
func IdentityRoleAllows(role identitymodel.RoleSchema, objectKey, action string) bool {
	return identitycontract.IdentityRoleAllows(role, objectKey, action)
}

// IdentityRoleAllowsData reports whether the role's data permission grants the
// requested read/export or write action for an object.
func IdentityRoleAllowsData(role identitymodel.RoleSchema, objectKey, action string) bool {
	return identitycontract.IdentityRoleAllowsData(role, objectKey, action)
}

// IdentityDataScopeForAction resolves the role's record scope for an object action.
func IdentityDataScopeForAction(role identitymodel.RoleSchema, objectKey, action string) string {
	return identitycontract.IdentityDataScopeForAction(role, objectKey, action)
}

// IdentityDataScope resolves a role's read or write scope for an object.
func IdentityDataScope(role identitymodel.RoleSchema, objectKey string, write bool) string {
	return identitycontract.IdentityDataScope(role, objectKey, write)
}
