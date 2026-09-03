package identity

import (
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func identityTestRolePermissions(keys ...string) []identitymodel.RolePermission {
	return identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, keys...)
}

func identityTestScopedRolePermissions(scope identitymodel.IdentityDataScope, keys ...string) []identitymodel.RolePermission {
	return identitymodel.RolePermissionsWithScope(scope, keys...)
}

func identityAllowAllRoleAssignments(principal identitymodel.Principal) identitymodel.Principal {
	permissions, valid := identitymodel.NormalizeRolePermissions(append(
		principal.Role.Permissions,
		identityTestRolePermissions(
			identitycontract.IdentityUserRoleAssignmentsAssignableRolesPermission,
			identitycontract.IdentityUserRoleAssignmentsAccountUpdatePermission,
			identitycontract.IdentityUserRoleAssignmentsAssignPermission,
			identitycontract.IdentityUserRoleAssignmentsRevokePermission,
			identitycontract.IdentityRoleRequestsApprovePermission,
			identitycontract.IdentityEntitlementsBatchPermission,
		)...,
	))
	if !valid {
		panic("identity test principal contains duplicate or invalid permissions")
	}
	principal.Role.Permissions = permissions
	return principal
}
