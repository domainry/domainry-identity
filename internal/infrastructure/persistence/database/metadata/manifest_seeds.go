package metadata

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"

	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
)

func manifestMetadataSeeds(seed manifestmodel.ManifestSchema) ([]metadataResourceSeed, error) {
	version := strings.TrimSpace(seed.Version)
	if version == "" {
		version = "1"
	}
	sourceID := strings.TrimSpace(seed.TemplateID)
	if sourceID == "" {
		sourceID = "generated-template"
	}
	newSeed := func(resourceType, table, key, objectKey, name string, payload any) (metadataResourceSeed, error) {
		key = strings.TrimSpace(key)
		if key == "" {
			return metadataResourceSeed{}, fmt.Errorf("%s metadata key is required", resourceType)
		}
		return metadataResourceSeed{
			ResourceType:  resourceType,
			Table:         table,
			Key:           key,
			ObjectKey:     strings.TrimSpace(objectKey),
			Name:          strings.TrimSpace(name),
			SchemaVersion: version,
			SourceKind:    "generated",
			SourceID:      sourceID,
			Payload:       payload,
		}, nil
	}
	seeds := []metadataResourceSeed{}
	appendSeed := func(resourceType, table, key, objectKey, name string, payload any) error {
		seed, err := newSeed(resourceType, table, key, objectKey, name, payload)
		if err != nil {
			return err
		}
		seeds = append(seeds, seed)
		return nil
	}
	appendDerivedSeed := func(resourceType, table, key, objectKey, name string, payload any) {
		seeds = append(seeds, metadataResourceSeed{
			ResourceType: resourceType, Table: table, Key: strings.TrimSpace(key), ObjectKey: strings.TrimSpace(objectKey), Name: strings.TrimSpace(name),
			SchemaVersion: version, SourceKind: "generated", SourceID: sourceID, Payload: payload,
		})
	}
	for _, object := range seed.Objects {
		objectCopy := object
		objectCopy.Fields = nil
		objectCopy.Validations = nil
		if err := appendSeed("object", "object_definitions", object.Key, object.Key, object.Name, objectCopy); err != nil {
			return nil, err
		}
		for _, field := range object.Fields {
			fieldCopy := field
			config := map[string]any{}
			for key, value := range field.Config {
				config[key] = value
			}
			config["_definition_object_key"] = object.Key
			fieldCopy.Config = config
			fieldKey := metadataJoinedKey(object.Key, field.Key)
			appendDerivedSeed("field", "field_definitions", fieldKey, object.Key, field.Name, fieldCopy)
		}
		for index, validation := range object.Validations {
			if strings.TrimSpace(validation.ObjectKey) == "" {
				validation.ObjectKey = object.Key
			}
			key := validation.Key
			if strings.TrimSpace(key) == "" {
				key = validationMetadataKey(object.Key, index, validation)
			}
			appendDerivedSeed("validation", "validation_definitions", key, validation.ObjectKey, validation.Message, validation)
		}
	}
	for _, view := range seed.Views {
		if err := appendSeed("view", "view_definitions", view.Key, view.ObjectKey, view.Name, view); err != nil {
			return nil, err
		}
	}
	for _, action := range seed.Actions {
		if err := appendSeed("action", "action_definitions", action.Key, action.ObjectKey, action.Label, action); err != nil {
			return nil, err
		}
	}
	roles := append([]identitymodel.RoleSchema(nil), seed.Roles...)
	roles = appendSystemRoleDefinition(roles, "identity_effective", "Identity Effective")
	for _, role := range roles {
		if err := appendSeed("role", "role_definitions", role.Key, "", role.Name, role); err != nil {
			return nil, err
		}
	}
	for _, binding := range seed.IdentityProfileExtensions {
		if err := appendSeed("identity_profile_binding", "identity_profile_binding_definitions", binding.ObjectKey, binding.ObjectKey, binding.BusinessIdentity.Key, binding); err != nil {
			return nil, err
		}
	}
	return seeds, nil
}

func metadataPayload(payload any) ([]byte, string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

func metadataResourceID(resourceType, key string) string {
	return strings.TrimSpace(resourceType) + ":" + strings.TrimSpace(key)
}

func metadataHashPrefix(hash string) string {
	hash = strings.TrimSpace(hash)
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

func metadataJoinedKey(left, right string) string {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	return left + "." + right
}

func metadataFieldObjectKey(field definitionmodel.FieldSchema) string {
	if value, ok := field.Config["_definition_object_key"]; ok {
		text := strings.TrimSpace(fmt.Sprint(value))
		if text != "" && text != "<nil>" {
			return text
		}
	}
	if value, ok := field.Config["definition_object_key"]; ok {
		text := strings.TrimSpace(fmt.Sprint(value))
		if text != "" && text != "<nil>" {
			return text
		}
	}
	return ""
}

func validationMetadataKey(objectKey string, index int, validation definitionmodel.ValidationSchema) string {
	parts := []string{objectKey, validation.Type, validation.FieldKey, strings.Join(validation.Fields, "_")}
	out := []string{}
	for _, part := range parts {
		if text := strings.Trim(strings.TrimSpace(part), "."); text != "" {
			out = append(out, text)
		}
	}
	if len(out) == 0 {
		return fmt.Sprintf("%s.validation.%d", strings.TrimSpace(objectKey), index+1)
	}
	return strings.Join(out, ".")
}

func metadataMapString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			text := strings.TrimSpace(fmt.Sprint(value))
			if text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}
