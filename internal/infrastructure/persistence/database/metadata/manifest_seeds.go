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
	newSeed := func(resourceType, key, objectKey, name string, payload any) (metadataResourceSeed, error) {
		key = strings.TrimSpace(key)
		if key == "" {
			return metadataResourceSeed{}, fmt.Errorf("%s metadata key is required", resourceType)
		}
		return metadataResourceSeed{
			ResourceType:  resourceType,
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
	appendSeed := func(resourceType, key, objectKey, name string, payload any) error {
		seed, err := newSeed(resourceType, key, objectKey, name, payload)
		if err != nil {
			return err
		}
		seeds = append(seeds, seed)
		return nil
	}
	roles := append([]identitymodel.RoleSchema(nil), seed.Roles...)
	roles = appendSystemRoleDefinition(roles, "identity_effective", "Identity Effective")
	for _, role := range roles {
		if err := appendSeed("role", role.Key, "", role.Name, role); err != nil {
			return nil, err
		}
	}
	for _, binding := range seed.IdentityProfileExtensions {
		if err := appendSeed("identity_profile_binding", binding.ObjectKey, binding.ObjectKey, binding.BusinessIdentity.Key, binding); err != nil {
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
