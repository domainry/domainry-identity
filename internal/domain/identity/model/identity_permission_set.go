package identitymodel

// IdentityPermissionSet is a reusable non-functional field/reference/export
// policy package. Exact scoped Action grants live only on RoleSchema.
type IdentityPermissionSet struct {
	Key                  string                `json:"key"`
	Name                 string                `json:"name"`
	Description          string                `json:"description,omitempty"`
	FieldPermissions     []FieldPermission     `json:"field_permissions,omitempty"`
	ReferencePermissions []ReferencePermission `json:"reference_permissions,omitempty"`
	ExportRules          []ExportRule          `json:"export_rules,omitempty"`
}

// IdentityPermissionSetGroup composes permission sets without becoming a
// directly assignable identity.
type IdentityPermissionSetGroup struct {
	Key               string   `json:"key"`
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	PermissionSetKeys []string `json:"permission_set_keys"`
}
