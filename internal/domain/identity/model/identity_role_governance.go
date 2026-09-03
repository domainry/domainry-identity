package identitymodel

// IdentityRoleGovernanceDetail is the read-only governance projection for one
// published role. It composes existing Identity authorities and must never be
// used as an alternative role write model.
type IdentityRoleGovernanceDetail struct {
	Role                IdentityRole                       `json:"role"`
	Definition          RoleSchema                         `json:"definition"`
	PermissionSets      []IdentityPermissionSet            `json:"permission_sets"`
	PermissionSetGroups []IdentityPermissionSetGroup       `json:"permission_set_groups"`
	Guardrails          []IdentityGuardrailPolicy          `json:"guardrails"`
	Permissions         []IdentityRolePermissionAssignment `json:"permissions"`
	FieldPermissions    []IdentityFieldPermission          `json:"field_permissions"`
	ExportRules         []ExportRule                       `json:"export_rules"`
	Menus               []IdentityMenu                     `json:"menus"`
	Members             []IdentityUserRoleAssignment       `json:"members"`
}
