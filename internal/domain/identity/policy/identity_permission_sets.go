package policy

import identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

// ExpandRolePermissionSets projects reusable non-functional policy into
// effective role definitions. It never expands RoleSchema.Permissions.
func ExpandRolePermissionSets(roles []identitymodel.RoleSchema, sets []identitymodel.IdentityPermissionSet, groups []identitymodel.IdentityPermissionSetGroup) []identitymodel.RoleSchema {
	return identitymodel.IdentityExpandRoleAuthorization(roles, sets, groups, nil)
}

// ExpandRoleAuthorization resolves non-functional policy packages and separate
// deny-only guardrails into effective role definitions.
func ExpandRoleAuthorization(roles []identitymodel.RoleSchema, sets []identitymodel.IdentityPermissionSet, groups []identitymodel.IdentityPermissionSetGroup, guardrails []identitymodel.IdentityGuardrailPolicy) []identitymodel.RoleSchema {
	return identitymodel.IdentityExpandRoleAuthorization(roles, sets, groups, guardrails)
}
