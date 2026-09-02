package contract

// IdentityBuiltinAuthorizationOwner is the canonical owner of Identity's
// source-owned built-in Action manifest.
const IdentityBuiltinAuthorizationOwner = "identity:builtin"

// These keys are referenced outside the manifest's route binding table by
// application services that retain final domain authorization checks.
const (
	IdentityActionAuthResetPassword            = "auth.reset_password"
	IdentityActionAuthProvidersSetup           = "auth.providers.setup"
	IdentityActionUsersForceLogout             = "identity.users.force_logout"
	IdentityActionProfileBindingsGet           = "identity.profile_bindings.get"
	IdentityActionProfileBindingsCommand       = "identity.profile_bindings.command"
	IdentityActionRolesList                    = "identity.roles.list"
	IdentityActionRolesSearch                  = "identity.roles.search"
	IdentityActionRolesGet                     = "identity.roles.get"
	IdentityActionRolesCreate                  = "identity.roles.create"
	IdentityActionRolesUpdate                  = "identity.roles.update"
	IdentityActionRolesDelete                  = "identity.roles.delete"
	IdentityActionRolesGovernanceDetail        = "identity.roles.governance_detail"
	IdentityActionRolesVersions                = "identity.roles.versions"
	IdentityActionRolesValidateGovernance      = "identity.roles.validate_governance"
	IdentityActionRolesValidate                = "identity.roles.validate"
	IdentityActionRolesImpactPreview           = "identity.roles.impact_preview"
	IdentityActionPermissionsList              = "identity.permissions.list"
	IdentityActionPermissionsSetEnabled        = "identity.permissions.set_enabled"
	IdentityActionRolePermissionsList          = "identity.role_permissions.list"
	IdentityActionRolePermissionsValidate      = "identity.role_permissions.validate"
	IdentityActionRolePermissionsPublish       = "identity.role_permissions.publish"
	IdentityActionRoleDataScopesList           = "identity.role_data_scopes.list"
	IdentityActionRoleDataScopesValidate       = "identity.role_data_scopes.validate"
	IdentityActionRoleDataScopesPublish        = "identity.role_data_scopes.publish"
	IdentityActionRoleFieldPermissionsList     = "identity.role_field_permissions.list"
	IdentityActionRoleFieldPermissionsValidate = "identity.role_field_permissions.validate"
	IdentityActionRoleFieldPermissionsPublish  = "identity.role_field_permissions.publish"
)
