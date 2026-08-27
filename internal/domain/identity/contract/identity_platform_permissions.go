package contract

// IdentityPlatformPermissionKeys is the backend-owned catalog of permissions
// exposed by the standalone Identity service. Effective-permission projections use this catalog to
// publish implicit grants (for example workspace administrator authority)
// without requiring a frontend role-name or permission-name fallback.
func IdentityPlatformPermissionKeys() []string {
	return []string{
		"portal.self_register",
		"workspace.admin",
		"identity.users.read",
		"identity.users.write",
		"identity.departments.read",
		"identity.departments.write",
		"identity.workforce.read",
		"identity.workforce.write",
		"identity.roles.read",
		"identity.roles.write",
		"identity.menus.read",
		"identity.menus.write",
		"identity.permissions.read",
		"identity.permissions.write",
		"identity.data_scopes.read",
		"identity.data_scopes.write",
		"identity.field_permissions.read",
		"identity.field_permissions.write",
		"identity.security.read",
		"identity.security.write",
		"identity.profile_binding.manage",
		"identity.permission.configure",
		"identity.audit.view",
		"audit.governance.read",
		"audit.governance.export",
		"metadata.read",
		"metadata.write",
	}
}
