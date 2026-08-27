package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

type metadataDefinitionPayloadShape struct {
	Key       string
	ObjectKey string
	Name      string
	Payload   any
}

func metadataDefinitionTable(resourceType string) (string, error) {
	switch strings.TrimSpace(resourceType) {
	case "object":
		return "object_definitions", nil
	case "field":
		return "field_definitions", nil
	case "validation":
		return "validation_definitions", nil
	case "view":
		return "view_definitions", nil
	case "action":
		return "action_definitions", nil
	case "role":
		return "role_definitions", nil
	case "identity_profile_binding":
		return "identity_profile_binding_definitions", nil
	default:
		return "", fmt.Errorf("unsupported Identity metadata resource type %q", resourceType)
	}
}

func metadataDefinitionShape(_ context.Context, resourceType, resourceKey string, req metadatamodel.MetadataDefinitionUpsertRequest) (metadataDefinitionPayloadShape, error) {
	switch strings.TrimSpace(resourceType) {
	case "object":
		var payload definitionmodel.ObjectSchema
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return metadataDefinitionPayloadShape{}, err
		}
		payload.Fields, payload.Validations = nil, nil
		key := valueOrFirstNonEmpty(resourceKey, payload.Key)
		payload.Key = key
		return metadataDefinitionPayloadShape{Key: key, ObjectKey: key, Name: valueOrFirstNonEmpty(req.Name, payload.Name), Payload: payload}, metadataDefinitionKeyError("object", key)
	case "field":
		var payload definitionmodel.FieldSchema
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return metadataDefinitionPayloadShape{}, err
		}
		if strings.TrimSpace(payload.Key) == "" || strings.TrimSpace(payload.Type) == "" {
			return metadataDefinitionPayloadShape{}, fmt.Errorf("metadata.field.invalidShape")
		}
		objectKey := valueOrFirstNonEmpty(req.ObjectKey, metadataFieldObjectKey(payload))
		key := valueOrFirstNonEmpty(resourceKey, metadataJoinedKey(objectKey, payload.Key))
		if payload.Config == nil {
			payload.Config = map[string]any{}
		}
		payload.Config["_definition_object_key"] = objectKey
		return metadataDefinitionPayloadShape{Key: key, ObjectKey: objectKey, Name: valueOrFirstNonEmpty(req.Name, payload.Name), Payload: payload}, metadataDefinitionKeyError("field", key)
	case "validation":
		var payload definitionmodel.ValidationSchema
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return metadataDefinitionPayloadShape{}, err
		}
		payload.ObjectKey = valueOrFirstNonEmpty(req.ObjectKey, payload.ObjectKey)
		payload.Key = valueOrFirstNonEmpty(resourceKey, payload.Key)
		return metadataDefinitionPayloadShape{Key: payload.Key, ObjectKey: payload.ObjectKey, Name: valueOrFirstNonEmpty(req.Name, payload.Message), Payload: payload}, metadataDefinitionKeyError("validation", payload.Key)
	case "view":
		var payload definitionmodel.ViewSchema
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return metadataDefinitionPayloadShape{}, err
		}
		payload.Key = valueOrFirstNonEmpty(resourceKey, payload.Key)
		payload.ObjectKey = valueOrFirstNonEmpty(req.ObjectKey, payload.ObjectKey)
		return metadataDefinitionPayloadShape{Key: payload.Key, ObjectKey: payload.ObjectKey, Name: valueOrFirstNonEmpty(req.Name, payload.Name), Payload: payload}, metadataDefinitionKeyError("view", payload.Key)
	case "action":
		var payload definitionmodel.ActionSchema
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return metadataDefinitionPayloadShape{}, err
		}
		payload.Key = valueOrFirstNonEmpty(resourceKey, payload.Key)
		payload.ObjectKey = valueOrFirstNonEmpty(req.ObjectKey, payload.ObjectKey)
		if strings.TrimSpace(payload.ObjectKey) == "" || strings.TrimSpace(payload.Kind) == "" {
			return metadataDefinitionPayloadShape{}, fmt.Errorf("metadata.action.invalidShape")
		}
		return metadataDefinitionPayloadShape{Key: payload.Key, ObjectKey: payload.ObjectKey, Name: valueOrFirstNonEmpty(req.Name, payload.Label), Payload: payload}, metadataDefinitionKeyError("action", payload.Key)
	case "role":
		var payload identitymodel.RoleSchema
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return metadataDefinitionPayloadShape{}, err
		}
		payload.Key = valueOrFirstNonEmpty(resourceKey, payload.Key)
		return metadataDefinitionPayloadShape{Key: payload.Key, Name: valueOrFirstNonEmpty(req.Name, payload.Name), Payload: payload}, metadataDefinitionKeyError("role", payload.Key)
	case "identity_profile_binding":
		var payload identitymodel.IdentityProfileExtension
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return metadataDefinitionPayloadShape{}, err
		}
		payload.ObjectKey = valueOrFirstNonEmpty(resourceKey, payload.ObjectKey)
		return metadataDefinitionPayloadShape{Key: payload.ObjectKey, ObjectKey: payload.ObjectKey, Name: valueOrFirstNonEmpty(req.Name, payload.BusinessIdentity.Key, payload.ObjectKey), Payload: payload}, metadataDefinitionKeyError("identity_profile_binding", payload.ObjectKey)
	default:
		return metadataDefinitionPayloadShape{}, fmt.Errorf("unsupported Identity metadata resource type %q", resourceType)
	}
}

func metadataDefinitionKeyError(resourceType, key string) error {
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("metadata.%s.missingKey", resourceType)
	}
	return nil
}

func valueOrFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if text := strings.TrimSpace(value); text != "" {
			return text
		}
	}
	return ""
}

func appendSystemRoleDefinition(roles []identitymodel.RoleSchema, key, name string) []identitymodel.RoleSchema {
	key = strings.TrimSpace(key)
	if key == "" {
		return roles
	}
	for _, role := range roles {
		if role.Key == key {
			return roles
		}
	}
	return append(roles, identitymodel.RoleSchema{Key: key, Name: name, RecordScope: "all_records"})
}
