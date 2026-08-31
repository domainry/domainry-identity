package metadata

import (
	"fmt"
	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatasdk "github.com/domainry/domainry-metadata-sdk"
)

func metadataModuleOwnsDefinition(resourceType string) bool {
	switch strings.TrimSpace(resourceType) {
	case "object", "field", "validation", "action", "dictionary":
		return true
	default:
		return false
	}
}

func (s MetadataStore) metadataModuleDefinitions() (metadatasdk.Definitions, error) {
	binding := s.store.Metadata()
	if binding == nil || binding.Definitions() == nil {
		return nil, fmt.Errorf("Metadata definitions are unavailable")
	}
	return binding.Definitions(), nil
}

func metadataDefinitionFromModule(value metadatasdk.Definition) metadatamodel.MetadataDefinition {
	return metadatamodel.MetadataDefinition{
		ResourceType: value.ResourceType, ResourceKey: value.ResourceKey, ObjectKey: value.ObjectKey, Name: value.Name,
		Payload: append([]byte(nil), value.Payload...), SchemaVersion: value.SchemaVersion, SchemaHash: value.SchemaHash,
		SourceKind: value.SourceKind, SourceID: value.SourceID, DisabledAt: value.DisabledAt,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}
