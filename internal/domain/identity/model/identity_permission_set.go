package identitymodel

// IdentityPermissionSet is a reusable non-functional policy package. Functional
// Action grants live only in RoleSchema.Permissions; a permission set may compose
// data, field, reference, and export policy without granting an Action.
type IdentityPermissionSet struct {
	Key                  string                `json:"key"`
	Name                 string                `json:"name"`
	Description          string                `json:"description,omitempty"`
	DataPermissions      []DataPermission      `json:"data_permissions,omitempty"`
	FieldPermissions     []FieldPermission     `json:"field_permissions,omitempty"`
	ReferencePermissions []ReferencePermission `json:"reference_permissions,omitempty"`
	ExportRules          []ExportRule          `json:"export_rules,omitempty"`
}

// IdentityPermissionSetGroup composes non-functional permission sets without
// becoming an Action-grant authority or a directly assignable identity.
type IdentityPermissionSetGroup struct {
	Key               string   `json:"key"`
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	PermissionSetKeys []string `json:"permission_set_keys"`
}
