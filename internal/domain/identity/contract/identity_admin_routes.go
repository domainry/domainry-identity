package contract

// AdminRouteRequiredPermissions is the backend-owned registry used to keep
// role-menu associations aligned with the permissions required by each page.
func AdminRouteRequiredPermissions(route string) ([]string, bool) {
	required, registered := map[string][]string{
		"/admin/security/accounts":     {"identity.users.read"},
		"/admin/org/workforce":         {"identity.workforce.read"},
		"/admin/org/departments":       {"identity.departments.read"},
		"/admin/org/roles":             {"identity.roles.read"},
		"/admin/org/menus":             {"identity.menus.read"},
		"/admin/org/data-scopes":       {"identity.data_scopes.read"},
		"/admin/org/field-permissions": {"identity.field_permissions.read"},
		"/admin/system/metadata":       {"metadata.read"},
		"/admin/system/audit":          {"audit.governance.read"},
	}[route]
	return append([]string(nil), required...), registered
}
