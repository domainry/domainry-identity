package policy

import identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

// ExpandRolePermissionSets projects reusable positive grants into effective
// role definitions. Unknown references add no authority; publication
// validation owns the corresponding fail-closed diagnostic.
func ExpandRolePermissionSets(roles []identitymodel.RoleSchema, sets []identitymodel.IdentityPermissionSet, groups []identitymodel.IdentityPermissionSetGroup) []identitymodel.RoleSchema {
	return identitymodel.IdentityExpandRoleAuthorization(roles, sets, groups, nil)
}

// ExpandRoleAuthorization resolves positive permission packages and separate
// deny-only guardrails into effective role definitions.
func ExpandRoleAuthorization(roles []identitymodel.RoleSchema, sets []identitymodel.IdentityPermissionSet, groups []identitymodel.IdentityPermissionSetGroup, guardrails []identitymodel.IdentityGuardrailPolicy) []identitymodel.RoleSchema {
	return identitymodel.IdentityExpandRoleAuthorization(roles, sets, groups, guardrails)
}
