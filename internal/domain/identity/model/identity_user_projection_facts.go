package identitymodel

type IdentityUserProjectionFacts struct {
	RoleAssignments []IdentityUserRoleAssignment `json:"role_assignments"`
	ProfileBindings []IdentityProfileBinding     `json:"profile_bindings"`
}
