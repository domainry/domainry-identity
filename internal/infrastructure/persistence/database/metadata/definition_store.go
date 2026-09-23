package metadata

import (
	"context"
	"fmt"
	"strings"

	shareddefinition "github.com/domainry/domainry-foundation/definition"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatasdk "github.com/domainry/domainry-metadata-sdk"
)

func (s MetadataStore) ListMetadataDefinitions(ctx context.Context, resourceType, sourceID string) ([]metadatamodel.MetadataDefinition, error) {
	if !metadataModuleOwnsDefinition(resourceType) {
		return s.listIdentityDefinitions(ctx, resourceType, sourceID)
	}
	definitions, err := s.metadataModuleDefinitions()
	if err != nil {
		return nil, err
	}
	values, err := definitions.List(ctx, metadatasdk.DefinitionQuery{Owner: metadatasdk.DefinitionOwnerMetadata, ResourceType: resourceType, SourceID: strings.TrimSpace(sourceID)})
	if err != nil {
		return nil, fmt.Errorf("list %s definitions: %w", resourceType, err)
	}
	result := make([]metadatamodel.MetadataDefinition, len(values))
	for index, value := range values {
		result[index] = metadataDefinitionFromModule(value)
	}
	return result, nil
}

func (s MetadataStore) GetMetadataDefinition(ctx context.Context, resourceType, resourceKey string) (metadatamodel.MetadataDefinition, bool, error) {
	if !metadataModuleOwnsDefinition(resourceType) {
		return s.getIdentityDefinition(ctx, resourceType, resourceKey)
	}
	definitions, err := s.metadataModuleDefinitions()
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, err
	}
	value, found, err := definitions.Get(ctx, metadatasdk.DefinitionOwnerMetadata, resourceType, resourceKey)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, fmt.Errorf("get %s definition: %w", resourceType, err)
	}
	if !found {
		return metadatamodel.MetadataDefinition{}, false, nil
	}
	return metadataDefinitionFromModule(value), true, nil
}

func (s MetadataStore) ListMetadataDefinitionVersions(ctx context.Context, resourceType, resourceKey string) ([]metadatamodel.MetadataDefinitionVersion, error) {
	if !metadataModuleOwnsDefinition(resourceType) {
		return s.listIdentityDefinitionVersions(ctx, resourceType, resourceKey)
	}
	definitions, err := s.identityDefinitions()
	if err != nil {
		return nil, err
	}
	values, err := definitions.ListVersions(ctx, shareddefinition.VersionListQuery{
		Owner: shareddefinition.OwnerMetadata, ResourceType: strings.TrimSpace(resourceType), ResourceKey: strings.TrimSpace(resourceKey),
	})
	if err != nil {
		return nil, err
	}
	result := make([]metadatamodel.MetadataDefinitionVersion, len(values))
	for index, value := range values {
		result[index] = metadataDefinitionVersionFromShared(value)
	}
	return result, nil
}
