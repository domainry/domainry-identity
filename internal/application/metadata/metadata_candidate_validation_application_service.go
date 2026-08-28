package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatavalidation "github.com/domainry/domainry-identity/internal/domain/metadata/validation"
)

// ValidateMetadataCandidate validates the complete Identity metadata graph
// after applying a Change Plan. Object, field, relation and authorization
// references are checked together so a multi-resource plan is atomic.
func (s *MetadataApplicationService) ValidateMetadataCandidate(ctx context.Context, mutations []metadatamodel.MetadataDefinitionMutation) error {
	if s == nil || s.repository == nil {
		return badRequest("backend.change_plan.candidate_invalid", "diagnostic", "metadata repository is unavailable")
	}
	candidate, err := s.repository.LoadManifest(ctx, metadataInstallationScope("validate Identity metadata candidate"))
	if err != nil {
		return wrapMetadataError(err)
	}
	activeActions := append([]definitionmodel.ActionSchema(nil), candidate.Actions...)
	for _, mutation := range mutations {
		if err := applyMetadataCandidateMutation(&candidate, mutation); err != nil {
			return badRequest("backend.change_plan.candidate_invalid", "resource_type", mutation.ResourceType, "resource_key", mutation.ResourceKey, "diagnostic", err.Error())
		}
	}
	if err := metadatavalidation.MetadataValidateIdentitySchemaWithAuthorizationObjects(candidate, s.currentAuthorizationObjects()); err != nil {
		return badRequest("backend.change_plan.candidate_invalid", "diagnostic", err.Error())
	}
	if err := validateRetiredActionPermissionAssignments(activeActions, candidate.Actions, candidate.Roles); err != nil {
		return badRequest("backend.change_plan.candidate_invalid", "diagnostic", err.Error())
	}
	for _, action := range candidate.Actions {
		if issues := validateBusinessActionDefinitionIssuesWithObjects(action, candidate.Objects); len(issues) > 0 {
			return badRequest("backend.change_plan.candidate_invalid", "resource_type", "action", "resource_key", action.Key, "diagnostic", issues[0].ErrorCode+":"+issues[0].FieldPath)
		}
	}
	return nil
}

// ValidateCurrentRuntimeDefinitions verifies the persisted Identity graph.
// The second argument remains for source compatibility with the old Runtime.
func (s *MetadataApplicationService) ValidateCurrentRuntimeDefinitions(ctx context.Context, _ any) error {
	return s.ValidateMetadataCandidate(ctx, nil)
}

func applyMetadataCandidateMutation(candidate *manifestmodel.ManifestSchema, mutation metadatamodel.MetadataDefinitionMutation) error {
	resourceType := strings.TrimSpace(mutation.ResourceType)
	resourceKey := strings.TrimSpace(mutation.ResourceKey)
	remove := mutation.Operation == "archive" || mutation.Operation == "delete"
	if mutation.Operation == "noop" {
		return nil
	}
	if !remove && mutation.Operation != "create" && mutation.Operation != "update" {
		return fmt.Errorf("unsupported operation %q", mutation.Operation)
	}
	payload := mutation.Request.Payload
	switch resourceType {
	case "object":
		if remove {
			candidate.Objects = candidateRemove(candidate.Objects, resourceKey, func(value definitionmodel.ObjectSchema) string { return value.Key })
			return nil
		}
		value, err := candidateDecode[definitionmodel.ObjectSchema](payload, resourceKey, func(value definitionmodel.ObjectSchema) string { return value.Key })
		if err != nil {
			return err
		}
		for _, current := range candidate.Objects {
			if current.Key == resourceKey {
				value.Fields, value.Validations = current.Fields, current.Validations
				break
			}
		}
		candidate.Objects = candidateReplace(candidate.Objects, resourceKey, value, func(value definitionmodel.ObjectSchema) string { return value.Key })
	case "field":
		return applyCandidateField(candidate, mutation, remove)
	case "validation":
		return applyCandidateValidation(candidate, mutation, remove)
	case "view":
		return candidateApplySlice(&candidate.Views, resourceKey, payload, remove, func(value definitionmodel.ViewSchema) string { return value.Key })
	case "action":
		return candidateApplySlice(&candidate.Actions, resourceKey, payload, remove, func(value definitionmodel.ActionSchema) string { return value.Key })
	case "role":
		return candidateApplySlice(&candidate.Roles, resourceKey, payload, remove, func(value identitymodel.RoleSchema) string { return value.Key })
	case "identity_profile_binding":
		return candidateApplySlice(&candidate.IdentityProfileExtensions, resourceKey, payload, remove, func(value identitymodel.IdentityProfileExtension) string { return value.ObjectKey })
	default:
		return fmt.Errorf("unsupported Identity metadata resource type %q", resourceType)
	}
	return nil
}

func applyCandidateField(candidate *manifestmodel.ManifestSchema, mutation metadatamodel.MetadataDefinitionMutation, remove bool) error {
	objectKey, fieldKey := candidateObjectMemberKey(mutation)
	index := candidateObjectIndex(candidate.Objects, objectKey)
	if index < 0 {
		return fmt.Errorf("field %s references unknown object %s", mutation.ResourceKey, objectKey)
	}
	if remove {
		candidate.Objects[index].Fields = candidateRemove(candidate.Objects[index].Fields, fieldKey, func(value definitionmodel.FieldSchema) string { return value.Key })
		return nil
	}
	value, err := candidateDecode[definitionmodel.FieldSchema](mutation.Request.Payload, fieldKey, func(value definitionmodel.FieldSchema) string { return value.Key })
	if err != nil {
		return err
	}
	candidate.Objects[index].Fields = candidateReplace(candidate.Objects[index].Fields, fieldKey, value, func(value definitionmodel.FieldSchema) string { return value.Key })
	return nil
}

func applyCandidateValidation(candidate *manifestmodel.ManifestSchema, mutation metadatamodel.MetadataDefinitionMutation, remove bool) error {
	objectKey := strings.TrimSpace(mutation.Request.ObjectKey)
	if objectKey == "" {
		var value definitionmodel.ValidationSchema
		_ = json.Unmarshal(mutation.Request.Payload, &value)
		objectKey = strings.TrimSpace(value.ObjectKey)
	}
	index := candidateObjectIndex(candidate.Objects, objectKey)
	if index < 0 {
		return fmt.Errorf("validation %s references unknown object %s", mutation.ResourceKey, objectKey)
	}
	if remove {
		candidate.Objects[index].Validations = candidateRemove(candidate.Objects[index].Validations, mutation.ResourceKey, func(value definitionmodel.ValidationSchema) string { return value.Key })
		return nil
	}
	value, err := candidateDecode[definitionmodel.ValidationSchema](mutation.Request.Payload, mutation.ResourceKey, func(value definitionmodel.ValidationSchema) string { return value.Key })
	if err != nil {
		return err
	}
	if strings.TrimSpace(value.ObjectKey) != objectKey {
		return fmt.Errorf("validation object key mismatch: expected %s, got %s", objectKey, value.ObjectKey)
	}
	candidate.Objects[index].Validations = candidateReplace(candidate.Objects[index].Validations, mutation.ResourceKey, value, func(value definitionmodel.ValidationSchema) string { return value.Key })
	return nil
}

func candidateObjectMemberKey(mutation metadatamodel.MetadataDefinitionMutation) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(mutation.ResourceKey), ".", 2)
	objectKey := strings.TrimSpace(mutation.Request.ObjectKey)
	fieldKey := ""
	if len(parts) == 2 {
		if objectKey == "" {
			objectKey = parts[0]
		}
		fieldKey = parts[1]
	}
	return objectKey, fieldKey
}
