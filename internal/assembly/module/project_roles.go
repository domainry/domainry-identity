package moduleassembly

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (binding *moduleBinding) PublishProjectRoles(ctx context.Context, catalog identitysdk.ProjectRoleCatalog) (identitysdk.ProjectRoleCatalogReceipt, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.Identity == nil || binding.runtime.IdentityStore == nil || binding.runtime.MetadataRuntime == nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, &identitysdk.Error{Code: "identity.project_role_catalog_unavailable"}
	}
	if catalog.Application.WorkspaceID != binding.application.WorkspaceID || catalog.Application.ApplicationKey != binding.application.ApplicationKey {
		return identitysdk.ProjectRoleCatalogReceipt{}, &identitysdk.Error{Code: "identity.project_role_catalog_scope_mismatch"}
	}
	projectObjects := []definitionmodel.ObjectSchema{}
	if err := decodeProjectRolePolicy(catalog.Objects, &projectObjects); err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	definitions := make([]identitymodel.RoleSchema, 0, len(catalog.Roles))
	seen := map[string]bool{}
	for _, input := range catalog.Roles {
		definition, err := projectRoleDefinition(input)
		if err != nil {
			return identitysdk.ProjectRoleCatalogReceipt{}, err
		}
		if seen[definition.Key] {
			return identitysdk.ProjectRoleCatalogReceipt{}, &identitysdk.Error{Code: "identity.project_role_duplicate"}
		}
		seen[definition.Key] = true
		definitions = append(definitions, definition)
	}

	workspaceID := string(catalog.Application.WorkspaceID)
	existing, err := binding.runtime.IdentityStore.ListIdentityRoles(ctx, workspaceID)
	if err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	byKey := map[string]identitymodel.IdentityRole{}
	for _, role := range existing {
		byKey[strings.TrimSpace(role.Key)] = role
	}
	for _, definition := range definitions {
		role := byKey[definition.Key]
		if role.ID == "" {
			role.ID = definition.Key
			role.Key = definition.Key
		}
		role.Label = definition.Name
		role.Status = identitymodel.IdentityStatusActive
		if err := binding.runtime.IdentityStore.UpsertIdentityRole(ctx, workspaceID, role); err != nil {
			return identitysdk.ProjectRoleCatalogReceipt{}, fmt.Errorf("sync project role %s: %w", definition.Key, err)
		}
	}
	merged := map[string]identitymodel.RoleSchema{}
	for _, definition := range binding.runtime.Identity.PublishedRoleDefinitions(ctx) {
		merged[definition.Key] = definition
	}
	for _, definition := range definitions {
		merged[definition.Key] = definition
	}
	all := make([]identitymodel.RoleSchema, 0, len(merged))
	for _, definition := range merged {
		all = append(all, definition)
	}
	binding.runtime.MetadataRuntime.ReplaceProjectObjects(projectObjects)
	binding.runtime.Identity.ReplaceRoleDefinitions(all)

	canonical, err := json.Marshal(catalog)
	if err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	digest := sha256.Sum256(canonical)
	return identitysdk.ProjectRoleCatalogReceipt{Published: len(definitions), SHA256: fmt.Sprintf("%x", digest[:])}, nil
}

func projectRoleDefinition(input identitysdk.ProjectRoleDefinition) (identitymodel.RoleSchema, error) {
	key, name := strings.TrimSpace(input.Key), strings.TrimSpace(input.Name)
	if key == "" || name == "" {
		return identitymodel.RoleSchema{}, &identitysdk.Error{Code: "identity.project_role_invalid"}
	}
	definition := identitymodel.RoleSchema{
		Key: key, Name: name,
		Audience: identitymodel.IdentityRoleAudience(strings.TrimSpace(input.Audience)), RequiredBindingKey: strings.TrimSpace(input.RequiredBindingKey),
		AssignmentMode: identitymodel.IdentityRoleAssignmentMode(strings.TrimSpace(input.AssignmentMode)), RiskLevel: identitymodel.IdentityRoleRiskLevel(strings.TrimSpace(input.RiskLevel)),
		ConflictRoleKeys: append([]string(nil), input.ConflictRoleKeys...), GrantableRoleKeys: append([]string(nil), input.GrantableRoleKeys...),
		PermissionSetKeys: append([]string(nil), input.PermissionSetKeys...), PermissionSetGroups: append([]string(nil), input.PermissionSetGroups...), GuardrailKeys: append([]string(nil), input.GuardrailKeys...),
		ProvisionToWorkspaces: input.ProvisionToWorkspaces,
	}
	for _, permission := range input.Permissions {
		key := strings.TrimSpace(permission.PermissionKey)
		if key == "" || !permission.DataScope.Valid() {
			return identitymodel.RoleSchema{}, &identitysdk.Error{Code: "identity.project_role_permission_invalid"}
		}
		definition.Permissions = append(definition.Permissions, identitymodel.RolePermission{PermissionKey: key, DataScope: permission.DataScope, AuditDenial: permission.AuditDenial})
	}
	if normalized, valid := identitymodel.NormalizeRolePermissions(definition.Permissions); valid {
		definition.Permissions = normalized
	} else {
		return identitymodel.RoleSchema{}, &identitysdk.Error{Code: "identity.project_role_permission_invalid"}
	}
	if err := decodeProjectRolePolicy(input.FieldPermissions, &definition.FieldPermissions); err != nil {
		return identitymodel.RoleSchema{}, err
	}
	if err := decodeProjectRolePolicy(input.ReferencePermissions, &definition.ReferencePermissions); err != nil {
		return identitymodel.RoleSchema{}, err
	}
	if err := decodeProjectRolePolicy(input.ExportRules, &definition.ExportRules); err != nil {
		return identitymodel.RoleSchema{}, err
	}
	if err := decodeProjectRolePolicy(input.Guardrails, &definition.Guardrails); err != nil {
		return identitymodel.RoleSchema{}, err
	}
	return definition, nil
}

func decodeProjectRolePolicy(raw json.RawMessage, target any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return &identitysdk.Error{Code: "identity.project_role_policy_invalid", Cause: err}
	}
	return nil
}
