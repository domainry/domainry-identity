package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/entityid"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

// IdentityGlobalRoleCatalogApplicationService reconciles one SaaS-owned role
// catalog into installation-global rows. Tenant role authoring uses the
// metadata publication path and never enters this boundary.
type IdentityGlobalRoleCatalogApplicationService struct {
	repository  identityrepository.IdentityRepository
	identity    *IdentityApplicationService
	workspaceID string
}

func NewIdentityGlobalRoleCatalogApplicationService(repository identityrepository.IdentityRepository, identity *IdentityApplicationService, workspaceID string) (*IdentityGlobalRoleCatalogApplicationService, error) {
	if repository == nil || identity == nil {
		return nil, fmt.Errorf("Identity global role catalog dependencies are required")
	}
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	return &IdentityGlobalRoleCatalogApplicationService{repository: repository, identity: identity, workspaceID: workspace.String()}, nil
}

func (service *IdentityGlobalRoleCatalogApplicationService) Reconcile(ctx context.Context, catalog identitysdk.ProjectRoleCatalog) (identitysdk.ProjectRoleCatalogReceipt, error) {
	if service == nil || service.repository == nil || service.identity == nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.project_role_catalog_unavailable"}
	}
	sourceOwner := strings.TrimSpace(catalog.SourceOwner)
	if _, err := identitysdk.PermissionSnapshotHash(sourceOwner, nil); err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_catalog_owner_invalid", Cause: err}
	}
	definitions, err := globalProjectRoleDefinitions(catalog.Roles)
	if err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	existing, err := service.repository.ListIdentityRoles(ctx, service.workspaceID)
	if err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	menus, err := service.repository.ListIdentityMenus(ctx, service.workspaceID)
	if err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	menuIDs := make(map[string]string, len(menus)*2)
	for _, menu := range menus {
		if menu.Status != "" && menu.Status != identitymodel.IdentityStatusActive {
			continue
		}
		menuIDs[menu.MenuID] = menu.MenuID
		menuIDs[menu.Key] = menu.MenuID
	}
	byGlobalKey := make(map[string]identitymodel.IdentityRole)
	for _, role := range existing {
		if role.ScopeType == identitymodel.IdentityRoleScopeGlobal {
			byGlobalKey[role.Key] = role
		}
	}
	inputsByKey := make(map[string]identitysdk.ProjectRoleDefinition, len(catalog.Roles))
	for _, input := range catalog.Roles {
		inputsByKey[strings.TrimSpace(input.Key)] = input
	}
	active := make(map[string]bool, len(definitions))
	for _, definition := range definitions {
		active[definition.Key] = true
		role := byGlobalKey[definition.Key]
		if role.RoleID != "" && role.SourceOwner != sourceOwner {
			return identitysdk.ProjectRoleCatalogReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassConflict, Code: "identity.project_role_owner_conflict", Params: map[string]string{"role_key": definition.Key, "current_owner": role.SourceOwner}}
		}
		if role.RoleID == "" {
			role.RoleID = globalCatalogRoleID(sourceOwner, definition.Key)
		}
		role.WorkspaceID = ""
		role.ScopeType = identitymodel.IdentityRoleScopeGlobal
		role.SourceOwner = sourceOwner
		role.Key = definition.Key
		role.Label = definition.Name
		role.Description = definition.Description
		role.Definition = definition
		role.Status = identitymodel.IdentityStatusActive
		if err := service.repository.UpsertIdentityRole(ctx, service.workspaceID, role); err != nil {
			return identitysdk.ProjectRoleCatalogReceipt{}, fmt.Errorf("reconcile global role %s: %w", definition.Key, err)
		}
		requestedMenus := inputsByKey[definition.Key].MenuKeys
		resolvedMenus := make([]string, 0, len(requestedMenus))
		seenMenus := map[string]bool{}
		for _, key := range requestedMenus {
			key = strings.TrimSpace(key)
			menuID, found := menuIDs[key]
			if key == "" || !found {
				return identitysdk.ProjectRoleCatalogReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_menu_invalid", Params: map[string]string{"role_key": definition.Key, "menu_key": key}}
			}
			if !seenMenus[menuID] {
				seenMenus[menuID] = true
				resolvedMenus = append(resolvedMenus, menuID)
			}
		}
		sort.Strings(resolvedMenus)
		if err := service.repository.SetIdentityRoleMenus(ctx, service.workspaceID, role.RoleID, resolvedMenus); err != nil {
			return identitysdk.ProjectRoleCatalogReceipt{}, fmt.Errorf("reconcile global role menus %s: %w", definition.Key, err)
		}
	}
	for _, role := range existing {
		if role.ScopeType != identitymodel.IdentityRoleScopeGlobal || role.SourceOwner != sourceOwner || active[role.Key] {
			continue
		}
		role.Status = identitymodel.IdentityStatusDisabled
		if err := service.repository.UpsertIdentityRole(ctx, service.workspaceID, role); err != nil {
			return identitysdk.ProjectRoleCatalogReceipt{}, fmt.Errorf("retire global role %s: %w", role.Key, err)
		}
		if err := service.repository.SetIdentityRoleMenus(ctx, service.workspaceID, role.RoleID, nil); err != nil {
			return identitysdk.ProjectRoleCatalogReceipt{}, err
		}
	}
	all, err := service.repository.ListIdentityRoles(ctx, service.workspaceID)
	if err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	published := make([]identitymodel.RoleSchema, 0, len(all))
	for _, role := range all {
		if role.Status == identitymodel.IdentityStatusActive && strings.TrimSpace(role.Definition.Key) != "" {
			published = append(published, role.Definition)
		}
	}
	service.identity.ReplaceRoleDefinitions(published)
	canonical, err := json.Marshal(catalog)
	if err != nil {
		return identitysdk.ProjectRoleCatalogReceipt{}, err
	}
	digest := sha256.Sum256(canonical)
	return identitysdk.ProjectRoleCatalogReceipt{SourceOwner: sourceOwner, Published: len(definitions), SHA256: fmt.Sprintf("%x", digest[:])}, nil
}

func globalCatalogRoleID(sourceOwner, roleKey string) string {
	value, err := entityid.Derive("role", "identity.global-role", sourceOwner, roleKey)
	if err != nil {
		return ""
	}
	return value
}

func globalProjectRoleDefinitions(inputs []identitysdk.ProjectRoleDefinition) ([]identitymodel.RoleSchema, error) {
	definitions := make([]identitymodel.RoleSchema, 0, len(inputs))
	seen := map[string]bool{}
	for _, input := range inputs {
		key, name := strings.TrimSpace(input.Key), strings.TrimSpace(input.Name)
		if key == "" || name == "" || seen[key] {
			return nil, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_invalid"}
		}
		seen[key] = true
		definition := identitymodel.RoleSchema{
			Key: key, Name: name, Description: strings.TrimSpace(input.Description),
			Audience: identitymodel.IdentityRoleAudience(strings.TrimSpace(input.Audience)), RequiredBindingKey: strings.TrimSpace(input.RequiredBindingKey),
			AssignmentMode: identitymodel.IdentityRoleAssignmentMode(strings.TrimSpace(input.AssignmentMode)), RiskLevel: identitymodel.IdentityRoleRiskLevel(strings.TrimSpace(input.RiskLevel)),
			ConflictRoleKeys: append([]string(nil), input.ConflictRoleKeys...), GrantableRoleKeys: append([]string(nil), input.GrantableRoleKeys...),
			PermissionSetKeys: append([]string(nil), input.PermissionSetKeys...), PermissionSetGroups: append([]string(nil), input.PermissionSetGroups...), GuardrailKeys: append([]string(nil), input.GuardrailKeys...),
		}
		for _, permission := range input.Permissions {
			if err := permission.Validate(); err != nil {
				return nil, err
			}
			definition.Permissions = append(definition.Permissions, identitymodel.RolePermission{PermissionKey: strings.TrimSpace(permission.PermissionKey), DataScope: permission.DataScope, DataPolicy: permission.DataPolicy, AuditDenial: permission.AuditDenial})
		}
		if normalized, valid := identitymodel.NormalizeRolePermissions(definition.Permissions); valid {
			definition.Permissions = normalized
		} else {
			return nil, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_permission_invalid"}
		}
		for raw, target := range map[*json.RawMessage]any{
			&input.FieldPermissions:     &definition.FieldPermissions,
			&input.ReferencePermissions: &definition.ReferencePermissions,
			&input.ExportRules:          &definition.ExportRules,
			&input.Guardrails:           &definition.Guardrails,
		} {
			if len(*raw) != 0 && string(*raw) != "null" {
				if err := json.Unmarshal(*raw, target); err != nil {
					return nil, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_policy_invalid", Cause: err}
				}
			}
		}
		definitions = append(definitions, definition)
	}
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].Key < definitions[j].Key })
	return definitions, nil
}
