package contract

import authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"

// IdentityAuthoringDomain is the Identity owner's complete authoring catalog.
// Adding an Identity capability changes this owner entrypoint, not the central
// platform catalog.
func IdentityAuthoringDomain() authoringcontract.CapabilityAuthoringDomain {
	return authoringcontract.CapabilityAuthoringDomain{Key: "identity", Capabilities: []authoringcontract.CapabilityAuthoringDefinition{
		IdentityUserAuthoringCapability(), IdentityOrganizationUnitAuthoringCapability(), IdentityRoleAuthoringCapability(),
		IdentityUserRoleAssignmentAuthoringCapability(), IdentityRolePermissionAuthoringCapability(), IdentityRoleDataScopeAuthoringCapability(),
		IdentityRoleFieldPermissionAuthoringCapability(), IdentityMenuAuthoringCapability(), IdentityRoleMenuAssignmentAuthoringCapability(),
		IdentityProfileBindingAuthoringCapability(),
	}}
}
