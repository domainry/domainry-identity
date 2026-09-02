package identitymodel

type IdentityUserDirectoryFacts struct {
	RoleAssignments []IdentityUserRoleAssignment `json:"role_assignments"`
	ProfileBindings []IdentityProfileBinding     `json:"profile_bindings"`
}
