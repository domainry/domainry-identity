package metadata

import metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"

	actionvalidation "github.com/domainry/domainry-identity/internal/domain/action/validation"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
)

func validateBusinessActionDefinitionIssues(action definitionmodel.ActionSchema) []metadatamodel.MetadataDefinitionValidationIssue {
	return actionvalidation.ActionValidateDefinitionIssues(action)
}

func validateBusinessActionDefinitionIssuesWithObjects(action definitionmodel.ActionSchema, objects []definitionmodel.ObjectSchema) []metadatamodel.MetadataDefinitionValidationIssue {
	return actionvalidation.ActionValidateDefinitionIssuesWithObjects(action, objects)
}

// Action permissions are same-key definition-owned catalog entries. Removing
// an Action must update every Role assignment in the same system draft,
// otherwise publication would leave a grant with no executable semantics.
func validateRetiredActionPermissionAssignments(active, candidate []definitionmodel.ActionSchema, roles []identitymodel.RoleSchema) error {
	activeOwned := map[string]bool{}
	for _, action := range active {
		if key := strings.TrimSpace(action.Key); key != "" {
			activeOwned[key] = true
		}
	}
	for _, action := range candidate {
		delete(activeOwned, strings.TrimSpace(action.Key))
	}
	for _, role := range roles {
		for _, grant := range role.Permissions {
			permissionKey := strings.TrimSpace(grant.PermissionKey)
			if activeOwned[permissionKey] {
				return fmt.Errorf("role %s retains retired action permission %s at permissions", role.Key, permissionKey)
			}
		}
	}
	return nil
}

func ValidateStructuredMetadataDefinition(resourceType string, payload json.RawMessage) ([]metadatamodel.MetadataDefinitionValidationIssue, bool) {
	switch resourceType {
	case "action":
		var action definitionmodel.ActionSchema
		if err := json.Unmarshal(payload, &action); err != nil {
			return []metadatamodel.MetadataDefinitionValidationIssue{newMetadataDefinitionValidationIssue("backend.action.definition_invalid", "definition", "", "", nil)}, true
		}
		return validateBusinessActionDefinitionIssues(action), true
	default:
		return nil, false
	}
}

// CanonicalizeMetadataCandidate is the sole pre-publication projection. It
// validates the complete composed candidate first, removes
// client JSON representation differences, and always derives compiler-owned
// Action effect sets on the server.
func (s *MetadataApplicationService) CanonicalizeMetadataCandidate(ctx context.Context, mutations []metadatamodel.MetadataDefinitionMutation) ([]metadatamodel.MetadataDefinitionMutation, error) {
	if err := s.ValidateMetadataCandidate(ctx, mutations); err != nil {
		return nil, err
	}
	canonical := make([]metadatamodel.MetadataDefinitionMutation, len(mutations))
	copy(canonical, mutations)
	for index := range canonical {
		mutation := &canonical[index]
		if mutation.Operation == "archive" || mutation.Operation == "delete" || mutation.Operation == "noop" {
			continue
		}
		var payload any
		if strings.TrimSpace(mutation.ResourceType) == "action" {
			var action definitionmodel.ActionSchema
			// ValidateMetadataCandidate has already decoded this exact mutation.
			_ = json.Unmarshal(mutation.Request.Payload, &action)
			action.EffectSet = nil
			payload = action
		} else {
			// Candidate validation guarantees syntactically valid JSON here.
			_ = json.Unmarshal(mutation.Request.Payload, &payload)
		}
		normalized, _ := json.Marshal(payload)
		mutation.Request.Payload = normalized
	}
	return canonical, nil
}

// validateInstalledActionAuthorization closes Runtime metadata initialization:
// the compiler-bound manifest is written first, then the persisted Action and
// role grant matrix is read back and compared before Runtime may become ready.
func validateInstalledActionAuthorization(installed, persisted manifestmodel.ManifestSchema) error {
	persistedActions := make(map[string]definitionmodel.ActionSchema, len(persisted.Actions))
	for _, action := range persisted.Actions {
		persistedActions[strings.TrimSpace(action.Key)] = action
	}
	persistedRoles := make(map[string]identitymodel.RoleSchema, len(persisted.Roles))
	for _, role := range persisted.Roles {
		persistedRoles[strings.TrimSpace(role.Key)] = role
	}
	actionPermissions := make(map[string]struct{}, len(installed.Actions))
	for _, action := range installed.Actions {
		actionKey := strings.TrimSpace(action.Key)
		actionPermissions[actionKey] = struct{}{}
		persistedAction, exists := persistedActions[actionKey]
		if !exists {
			return fmt.Errorf("Runtime metadata initialization is incomplete: installed Action %q was not persisted", actionKey)
		}
		if strings.TrimSpace(persistedAction.Key) != actionKey {
			return fmt.Errorf("Runtime metadata initialization is incomplete: persisted Action key %q does not match %q", persistedAction.Key, actionKey)
		}
	}
	for _, installedRole := range installed.Roles {
		roleKey := strings.TrimSpace(installedRole.Key)
		persistedRole, exists := persistedRoles[roleKey]
		if !exists {
			return fmt.Errorf("Runtime metadata initialization is incomplete: installed role %q was not persisted", roleKey)
		}
		for permission := range actionPermissions {
			want := roleHasExactPermission(installedRole, permission)
			got := roleHasExactPermission(persistedRole, permission)
			if got == want {
				continue
			}
			return fmt.Errorf(
				"Runtime metadata initialization is incomplete: persisted role %q Action permission %q=%t, want %t",
				roleKey, permission, got, want,
			)
		}
	}
	return nil
}

func roleHasExactPermission(role identitymodel.RoleSchema, permission string) bool {
	for _, candidate := range role.Permissions {
		if strings.TrimSpace(candidate.PermissionKey) == permission && candidate.Valid() {
			return true
		}
	}
	return false
}
