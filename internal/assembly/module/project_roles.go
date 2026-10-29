package moduleassembly

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func (binding *moduleBinding) PublishProjectRoles(ctx context.Context, catalog identitysdk.ProjectRoleCatalog) (identitysdk.ProjectRoleCatalogReceipt, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.Identity == nil || binding.runtime.IdentityStore == nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.project_role_catalog_unavailable"}
	}
	sourceOwner := strings.TrimSpace(catalog.SourceOwner)
	if sourceOwner == "" {
		return identitysdk.ProjectRoleCatalogReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_catalog_owner_required"}
	}
	projectObjects := []definitionmodel.ObjectSchema{}
	if err := decodeProjectRolePolicy(catalog.Objects, &projectObjects); err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	definitions, err := projectRoleDefinitions(catalog.Roles)
	if err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}

	workspaceID := string(binding.application.WorkspaceID)
	existing, err := binding.runtime.IdentityStore.ListIdentityRoles(ctx, workspaceID)
	if err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	byKey := map[string]identitymodel.IdentityRole{}
	for _, role := range existing {
		byKey[strings.TrimSpace(role.Key)] = role
	}
	menuKeysByRole := make(map[string][]string, len(catalog.Roles))
	for _, input := range catalog.Roles {
		menuKeysByRole[strings.TrimSpace(input.Key)] = append([]string(nil), input.MenuKeys...)
	}
	active := make(map[string]bool, len(definitions))
	for _, definition := range definitions {
		active[definition.Key] = true
		role := byKey[definition.Key]
		if role.RoleID != "" && role.ScopeType == identitymodel.IdentityRoleScopeGlobal && role.SourceOwner != sourceOwner {
			return identitysdk.ProjectRoleCatalogReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassConflict, Code: "identity.project_role_owner_conflict", Params: map[string]string{"role_key": definition.Key, "current_owner": role.SourceOwner}}
		}
		if role.RoleID == "" {
			role.RoleID = identitypersistence.GlobalRoleID(sourceOwner, definition.Key)
			role.Key = definition.Key
		}
		role.Label = definition.Name
		role.Description = definition.Description
		role.ScopeType = identitymodel.IdentityRoleScopeGlobal
		role.SourceOwner = sourceOwner
		role.Definition = definition
		role.Status = identitymodel.IdentityStatusActive
		if err := binding.runtime.IdentityStore.UpsertIdentityRole(ctx, workspaceID, role); err != nil {
			return identitysdk.ProjectRoleCatalogReceipt{}, fmt.Errorf("sync project role %s: %w", definition.Key, err)
		}
		if err := binding.runtime.IdentityStore.SetIdentityRoleMenus(ctx, workspaceID, role.RoleID, menuKeysByRole[definition.Key]); err != nil {
			return identitysdk.ProjectRoleCatalogReceipt{}, fmt.Errorf("sync project role menus %s: %w", definition.Key, err)
		}
	}
	for _, role := range existing {
		if role.ScopeType != identitymodel.IdentityRoleScopeGlobal || role.SourceOwner != sourceOwner || active[role.Key] {
			continue
		}
		role.Status = identitymodel.IdentityStatusDisabled
		if err := binding.runtime.IdentityStore.UpsertIdentityRole(ctx, workspaceID, role); err != nil {
			return identitysdk.ProjectRoleCatalogReceipt{}, fmt.Errorf("retire project role %s: %w", role.Key, err)
		}
	}
	if binding.runtime.MetadataRuntime != nil {
		binding.runtime.MetadataRuntime.ReplaceProjectObjects(projectObjects)
		binding.runtime.MetadataRuntime.ReplaceProjectRoles(definitions)
		binding.runtime.Identity.ReplaceRoleDefinitions(
			binding.runtime.MetadataRuntime.EffectiveRoleDefinitions(
				binding.runtime.MetadataRuntime.Schema().Roles,
			),
		)
	} else {
		binding.runtime.Identity.ReplaceRoleDefinitions(definitions)
	}

	canonical, err := json.Marshal(catalog)
	if err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	digest := sha256.Sum256(canonical)
	return identitysdk.ProjectRoleCatalogReceipt{SourceOwner: sourceOwner, Published: len(definitions), SHA256: fmt.Sprintf("%x", digest[:])}, nil
}

// BindBootstrapProjectRoleCatalog makes application roles available to the
// first-Workspace provisioner without writing any Workspace-owned rows. The same
// project-role decoder used by ordinary publication validates the catalog;
// the host transaction remains the only place where workspace roles, users,
// organizations, assignments, and credentials are persisted.
func (binding *moduleBinding) BindBootstrapProjectRoleCatalog(ctx context.Context, catalog identitysdk.ProjectRoleCatalog) error {
	if binding == nil || binding.runtime == nil || binding.runtime.Identity == nil || binding.runtime.IdentityStore == nil {
		return &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.bootstrap_project_role_catalog_unavailable"}
	}
	if ctx == nil {
		return &identitysdk.Error{Class: identitysdk.ErrorClassInternal, Code: "identity.context_required"}
	}
	if err := ctx.Err(); err != nil {
		return &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.context_unavailable", Cause: err}
	}
	if err := catalog.ValidateContract(); err != nil {
		return err
	}
	// Global roles must exist before the first tenant transaction can assign
	// its administrator. Catalog publication is installation-scoped and is
	// intentionally outside the tenant bootstrap transaction.
	if _, err := binding.PublishProjectRoles(ctx, catalog); err != nil {
		return err
	}
	projectObjects := []definitionmodel.ObjectSchema{}
	if err := decodeProjectRolePolicy(catalog.Objects, &projectObjects); err != nil {
		return err
	}
	definitions, err := projectRoleDefinitions(catalog.Roles)
	if err != nil {
		return err
	}
	bootstrapCatalog, err := newWorkspaceBootstrapRoleCatalog(catalog.Roles, definitions, catalog.InitialWorkspaceAdministratorRoleKey)
	if err != nil {
		return err
	}
	byKey := make(map[string]identitymodel.RoleSchema, len(binding.runtime.Manifest.Roles)+len(definitions))
	for _, definition := range binding.runtime.Manifest.Roles {
		if key := strings.TrimSpace(definition.Key); key != "" {
			definition.Key = key
			byKey[key] = definition
		}
	}
	// Application-owned role definitions intentionally win on collisions, just
	// as they do after the ordinary workspace-bound binding is opened.
	for _, definition := range definitions {
		byKey[definition.Key] = definition
	}
	roles := make([]identitymodel.RoleSchema, 0, len(byKey))
	for _, definition := range byKey {
		roles = append(roles, definition)
	}
	sort.Slice(roles, func(left, right int) bool { return roles[left].Key < roles[right].Key })
	binding.runtime.Identity.ReplaceRoleDefinitions(roles)
	binding.bootstrapMu.Lock()
	bootstrapCatalog.sourceOwner = strings.TrimSpace(catalog.SourceOwner)
	binding.bootstrapRoleCatalog = bootstrapCatalog
	binding.bootstrapMu.Unlock()
	return nil
}

func projectRoleDefinitions(inputs []identitysdk.ProjectRoleDefinition) ([]identitymodel.RoleSchema, error) {
	definitions := make([]identitymodel.RoleSchema, 0, len(inputs))
	seen := map[string]bool{}
	for _, input := range inputs {
		definition, err := projectRoleDefinition(input)
		if err != nil {
			return nil, err
		}
		if seen[definition.Key] {
			return nil, &identitysdk.Error{Class: identitysdk.ErrorClassConflict, Code: "identity.project_role_duplicate"}
		}
		seen[definition.Key] = true
		definitions = append(definitions, definition)
	}
	return definitions, nil
}

func projectRoleDefinition(input identitysdk.ProjectRoleDefinition) (identitymodel.RoleSchema, error) {
	key, name := strings.TrimSpace(input.Key), strings.TrimSpace(input.Name)
	if key == "" || name == "" {
		return identitymodel.RoleSchema{}, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_invalid"}
	}
	definition := identitymodel.RoleSchema{
		Key: key, Name: name, Description: strings.TrimSpace(input.Description),
		Audience: identitymodel.IdentityRoleAudience(strings.TrimSpace(input.Audience)), RequiredBindingKey: strings.TrimSpace(input.RequiredBindingKey),
		AssignmentMode: identitymodel.IdentityRoleAssignmentMode(strings.TrimSpace(input.AssignmentMode)), RiskLevel: identitymodel.IdentityRoleRiskLevel(strings.TrimSpace(input.RiskLevel)),
		ConflictRoleKeys: append([]string(nil), input.ConflictRoleKeys...), GrantableRoleKeys: append([]string(nil), input.GrantableRoleKeys...),
		PermissionSetKeys: append([]string(nil), input.PermissionSetKeys...), PermissionSetGroups: append([]string(nil), input.PermissionSetGroups...), GuardrailKeys: append([]string(nil), input.GuardrailKeys...),
	}
	for _, permission := range input.Permissions {
		key := strings.TrimSpace(permission.PermissionKey)
		if err := permission.Validate(); key == "" || err != nil {
			return identitymodel.RoleSchema{}, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_permission_invalid"}
		}
		definition.Permissions = append(definition.Permissions, identitymodel.RolePermission{PermissionKey: key, DataScope: permission.DataScope, DataPolicy: permission.DataPolicy, AuditDenial: permission.AuditDenial})
	}
	if normalized, valid := identitymodel.NormalizeRolePermissions(definition.Permissions); valid {
		definition.Permissions = normalized
	} else {
		return identitymodel.RoleSchema{}, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_permission_invalid"}
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
		return &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_policy_invalid", Cause: err}
	}
	return nil
}
