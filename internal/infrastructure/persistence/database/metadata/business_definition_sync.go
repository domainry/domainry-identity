package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatasdk "github.com/domainry/domainry-metadata-sdk"
)

func (s MetadataStore) syncBusinessMetadataDefinitions(ctx context.Context, manifest manifestmodel.ManifestSchema) error {
	binding := s.store.Metadata()
	if binding == nil || binding.Projection() == nil {
		return fmt.Errorf("Metadata projection is unavailable")
	}
	definitions := []metadatasdk.Definition{}
	appendDefinition := func(resourceType, key, objectKey, name string, value any) error {
		payload, err := json.Marshal(value)
		if err != nil {
			return err
		}
		definitions = append(definitions, metadatasdk.Definition{ResourceType: resourceType, ResourceKey: strings.TrimSpace(key), ObjectKey: strings.TrimSpace(objectKey), Name: strings.TrimSpace(name), Payload: payload})
		return nil
	}
	for _, object := range manifest.Objects {
		objectCopy := object
		objectCopy.Fields, objectCopy.Validations = nil, nil
		if err := appendDefinition("object", object.Key, object.Key, object.Name, objectCopy); err != nil {
			return err
		}
		for _, field := range object.Fields {
			fieldCopy := field
			fieldCopy.Config = cloneBusinessMetadataConfig(field.Config)
			fieldCopy.Config["_definition_object_key"] = object.Key
			if err := appendDefinition("field", metadataJoinedKey(object.Key, field.Key), object.Key, field.Name, fieldCopy); err != nil {
				return err
			}
		}
		for index, validation := range object.Validations {
			if strings.TrimSpace(validation.ObjectKey) == "" {
				validation.ObjectKey = object.Key
			}
			key := strings.TrimSpace(validation.Key)
			if key == "" {
				key = validationMetadataKey(object.Key, index, validation)
			}
			if err := appendDefinition("validation", key, validation.ObjectKey, validation.Message, validation); err != nil {
				return err
			}
		}
	}
	for _, action := range manifest.Actions {
		if err := appendDefinition("action", action.Key, action.ObjectKey, action.Label, action); err != nil {
			return err
		}
	}
	version := strings.TrimSpace(manifest.Version)
	if version == "" {
		version = "1"
	}
	sourceID := strings.TrimSpace(manifest.TemplateID)
	if sourceID == "" {
		sourceID = "generated-template"
	}
	return binding.Projection().Sync(ctx, metadatasdk.ProjectionSnapshot{
		SchemaVersion: version, SourceKind: "generated", SourceID: sourceID,
		Name: strings.TrimSpace(manifest.Name), DefaultLocale: strings.TrimSpace(manifest.DefaultLocale),
		Definitions: definitions,
	})
}

func cloneBusinessMetadataConfig(value map[string]any) map[string]any {
	result := make(map[string]any, len(value)+1)
	for key, item := range value {
		result[key] = item
	}
	return result
}
