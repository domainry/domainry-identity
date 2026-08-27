package contract

import authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"

func MetadataAuthoringDomain() authoringcontract.CapabilityAuthoringDomain {
	return authoringcontract.CapabilityAuthoringDomain{Key: "schema", Capabilities: MetadataAuthoringCapabilities()}
}

func MetadataViewAuthoringDomain() authoringcontract.CapabilityAuthoringDomain {
	return authoringcontract.CapabilityAuthoringDomain{Key: "view", Capabilities: MetadataViewAuthoringCapabilities()}
}

func MetadataAuthoringCapabilities() []authoringcontract.CapabilityAuthoringDefinition {
	capabilities := []authoringcontract.CapabilityAuthoringDefinition{MetadataObjectAuthoringCapability(), MetadataFieldAuthoringCapability(), MetadataRelationAuthoringCapability()}
	return append(capabilities, MetadataDictionaryAuthoringCapabilities()...)
}

func MetadataViewAuthoringCapabilities() []authoringcontract.CapabilityAuthoringDefinition {
	return []authoringcontract.CapabilityAuthoringDefinition{MetadataViewAuthoringCapability()}
}
