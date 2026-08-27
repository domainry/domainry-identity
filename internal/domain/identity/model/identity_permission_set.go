package identitymodel

// IdentityPermissionSet is a reusable positive authorization package. Roles
// reference permission sets; they remain the assignable business responsibility.
type IdentityPermissionSet struct {
	Key                  string                `json:"key"`
	Name                 string                `json:"name"`
	Description          string                `json:"description,omitempty"`
	Permissions          []string              `json:"permissions,omitempty"`
	DataPermissions      []DataPermission      `json:"data_permissions,omitempty"`
	FieldPermissions     []FieldPermission     `json:"field_permissions,omitempty"`
	ReferencePermissions []ReferencePermission `json:"reference_permissions,omitempty"`
	ExportRules          []ExportRule          `json:"export_rules,omitempty"`
}

// IdentityPermissionSetGroup composes reusable permission sets without making
// the group itself assignable to a user.
type IdentityPermissionSetGroup struct {
	Key               string   `json:"key"`
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	PermissionSetKeys []string `json:"permission_set_keys"`
}
