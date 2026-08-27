package identitymodel

type IdentityUserDirectoryFacts struct {
	RoleAssignments   []IdentityUserRoleAssignment `json:"role_assignments"`
	WorkforceProfiles []IdentityWorkforceProfile   `json:"workforce_profiles"`
	ProfileBindings   []IdentityProfileBinding     `json:"profile_bindings"`
}
