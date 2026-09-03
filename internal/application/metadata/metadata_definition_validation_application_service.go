package metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatavalidation "github.com/domainry/domainry-identity/internal/domain/metadata/validation"
)

func candidateObjectIndex(objects []definitionmodel.ObjectSchema, key string) int {
	for index := range objects {
		if strings.TrimSpace(objects[index].Key) == strings.TrimSpace(key) {
			return index
		}
	}
	return -1
}

func candidateApplySlice[T any](values *[]T, key string, payload json.RawMessage, remove bool, keyOf func(T) string) error {
	if remove {
		*values = candidateRemove(*values, key, keyOf)
		return nil
	}
	value, err := candidateDecode[T](payload, key, keyOf)
	if err != nil {
		return err
	}
	*values = candidateReplace(*values, key, value, keyOf)
	return nil
}

func candidateDecode[T any](payload json.RawMessage, expectedKey string, keyOf func(T) string) (T, error) {
	var value T
	if err := json.Unmarshal(payload, &value); err != nil {
		return value, err
	}
	actual := strings.TrimSpace(keyOf(value))
	if actual != strings.TrimSpace(expectedKey) {
		return value, fmt.Errorf("resource key mismatch: expected %s, got %s", expectedKey, actual)
	}
	return value, nil
}

func candidateReplace[T any](values []T, key string, value T, keyOf func(T) string) []T {
	out := make([]T, 0, len(values)+1)
	replaced := false
	for _, current := range values {
		if strings.TrimSpace(keyOf(current)) == strings.TrimSpace(key) {
			if !replaced {
				out = append(out, value)
				replaced = true
			}
			continue
		}
		out = append(out, current)
	}
	if !replaced {
		out = append(out, value)
	}
	return out
}

func candidateRemove[T any](values []T, key string, keyOf func(T) string) []T {
	out := make([]T, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(keyOf(value)) != strings.TrimSpace(key) {
			out = append(out, value)
		}
	}
	return out
}

func (s *MetadataApplicationService) ValidateMetadataDefinition(ctx context.Context, resourceType, resourceKey string, req metadatamodel.MetadataDefinitionUpsertRequest, principal identitymodel.Principal) (metadatamodel.MetadataDefinitionValidationResult, error) {
	if err := metadataAuthorizeQuery(principal); err != nil {
		return metadatamodel.MetadataDefinitionValidationResult{}, err
	}
	return metadatavalidation.MetadataValidateDefinitionRequest(ctx, resourceType, resourceKey, req.Payload, principal,
		func(ctx context.Context, resourceType, resourceKey string, payload json.RawMessage) (json.RawMessage, []metadatamodel.MetadataDefinitionValidationIssue, error) {
			req.Payload = payload
			return s.ValidateMetadataDefinitionRequestPayload(ctx, resourceType, resourceKey, req)
		})
}

func (s *MetadataApplicationService) ValidateMetadataDefinitionRequestPayload(ctx context.Context, resourceType, resourceKey string, req metadatamodel.MetadataDefinitionUpsertRequest) (json.RawMessage, []metadatamodel.MetadataDefinitionValidationIssue, error) {
	switch strings.TrimSpace(resourceType) {
	case "object":
		normalized, err := metadatavalidation.MetadataValidateObjectDefinition(resourceKey, req.Payload)
		return normalized, nil, err
	case "field":
		normalized, err := s.normalizeAndValidateFieldMetadataMutation(ctx, req)
		return normalized.Payload, nil, err
	case "validation":
		var validation definitionmodel.ValidationSchema
		if err := json.Unmarshal(req.Payload, &validation); err != nil {
			return nil, nil, badRequest("backend.metadata.validation_definition_invalid")
		}
		if validation.Key = strings.TrimSpace(validation.Key); validation.Key == "" || validation.Key != strings.TrimSpace(resourceKey) {
			return nil, nil, badRequest("backend.metadata.validation_definition_invalid")
		}
		if strings.TrimSpace(validation.ObjectKey) == "" {
			validation.ObjectKey = strings.TrimSpace(req.ObjectKey)
		}
		if strings.TrimSpace(validation.ObjectKey) == "" {
			return nil, nil, badRequest("backend.metadata.validation_definition_invalid")
		}
		normalized, err := json.Marshal(validation)
		return normalized, nil, err
	case "action":
		action, err := decodeActionDefinitionPayload(req.Payload)
		if err != nil {
			return nil, []metadatamodel.MetadataDefinitionValidationIssue{newMetadataDefinitionValidationIssue("backend.action.definition_invalid", "definition", "", "", nil)}, nil
		}
		if issues := validateBusinessActionDefinitionIssuesWithObjects(action, s.runtime.Schema().Objects); len(issues) > 0 {
			return nil, issues, nil
		}
		action.EffectSet = nil
		normalized, err := json.Marshal(action)
		return normalized, nil, err
	case "role":
		var role identitymodel.RoleSchema
		if err := json.Unmarshal(req.Payload, &role); err != nil || strings.TrimSpace(role.Key) != strings.TrimSpace(resourceKey) {
			return nil, nil, badRequest("backend.identity.role_definition_invalid")
		}
	case "identity_profile_binding":
		normalized, err := s.ValidateMetadataDefinitionPayload(ctx, resourceType, req)
		return normalized.Payload, nil, err
	default:
		return nil, nil, badRequest("backend.metadata.definition_type_unsupported", "resource_type", resourceType)
	}
	return req.Payload, nil, nil
}

func (s *MetadataApplicationService) ValidateMetadataDefinitionPayload(ctx context.Context, resourceType string, req metadatamodel.MetadataDefinitionUpsertRequest) (metadatamodel.MetadataDefinitionUpsertRequest, error) {
	switch strings.TrimSpace(resourceType) {
	case "field":
		return s.normalizeAndValidateFieldMetadataMutation(ctx, req)
	case "action":
		action, err := decodeActionDefinitionPayload(req.Payload)
		if err != nil {
			return req, badRequest("backend.action.definition_invalid")
		}
		if err := firstMetadataDefinitionIssueError(validateBusinessActionDefinitionIssuesWithObjects(action, s.runtime.Schema().Objects)); err != nil {
			return req, err
		}
		action.EffectSet = nil
		req.Payload, _ = json.Marshal(action)
		return req, nil
	case "identity_profile_binding":
		var binding identitymodel.IdentityProfileExtension
		if err := json.Unmarshal(req.Payload, &binding); err != nil {
			return req, badRequest("backend.identity.profile_binding_invalid")
		}
		if binding.ContractVersion == "" {
			binding.ContractVersion = identitymodel.IdentityProfileExtensionContractVersion
		}
		if binding.MinReaderVersion == "" {
			binding.MinReaderVersion = identitymodel.IdentityProfileExtensionMinReaderVersion
		}
		if binding.Cardinality == "" {
			binding.Cardinality = "one_to_one"
		}
		req.Payload, _ = json.Marshal(binding)
		snapshot := s.runtime.Schema()
		bindings := make([]identitymodel.IdentityProfileExtension, 0, len(snapshot.IdentityProfileExtensions)+1)
		for _, current := range snapshot.IdentityProfileExtensions {
			if current.ObjectKey != binding.ObjectKey {
				bindings = append(bindings, current)
			}
		}
		bindings = append(bindings, binding)
		candidate := identityMetadataManifest(snapshot)
		candidate.IdentityProfileExtensions = bindings
		if err := metadatavalidation.MetadataValidateIdentitySchema(candidate); err != nil {
			return req, badRequest("backend.identity.profile_binding_invalid", "diagnostic", err.Error())
		}
		return req, nil
	case "object", "role":
		return req, nil
	default:
		return req, badRequest("backend.metadata.definition_type_unsupported", "resource_type", resourceType)
	}
}

func decodeActionDefinitionPayload(payload json.RawMessage) (definitionmodel.ActionSchema, error) {
	var action definitionmodel.ActionSchema
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&action); err != nil {
		return definitionmodel.ActionSchema{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return definitionmodel.ActionSchema{}, fmt.Errorf("action definition contains trailing JSON value")
		}
		return definitionmodel.ActionSchema{}, err
	}
	return action, nil
}

func identityMetadataManifest(snapshot metadatamodel.MetadataSchemaSnapshot) manifestmodel.ManifestSchema {
	return manifestmodel.ManifestSchema{
		TemplateID:                snapshot.TemplateID,
		Version:                   snapshot.TemplateVersion,
		Name:                      snapshot.Name,
		Objects:                   snapshot.Objects,
		Actions:                   snapshot.Actions,
		Roles:                     snapshot.Roles,
		PermissionSets:            snapshot.PermissionSets,
		PermissionSetGroups:       snapshot.PermissionSetGroups,
		Guardrails:                snapshot.Guardrails,
		IdentityProfileExtensions: snapshot.IdentityProfileExtensions,
	}
}
