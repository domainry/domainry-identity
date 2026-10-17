package metadata

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-foundation/idempotency"
	auditcontract "github.com/domainry/domainry-identity/internal/application/auditbinding"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func (s *MetadataApplicationService) IdentityRolePermissionDefinition(ctx context.Context, roleKey string, principal identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	return s.identityRolePermissionDefinitionForAction(ctx, roleKey, identitycontract.IdentityActionRolePermissionsList, false, principal)
}

func (s *MetadataApplicationService) IdentityRolePermissionDefinitionForPublication(ctx context.Context, roleKey string, principal identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	return s.identityRolePermissionDefinitionForAction(ctx, roleKey, identitycontract.IdentityActionRolePermissionsPublish, true, principal)
}

func (s *MetadataApplicationService) identityRolePermissionDefinitionForAction(ctx context.Context, roleKey, actionKey string, command bool, principal identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	role, revision, found, err := s.identityRoleDefinitionForAction(ctx, roleKey, actionKey, command, principal)
	if err != nil {
		return role, revision, found, err
	}
	project, isProject := s.projectRoleDefinition(roleKey)
	if !isProject {
		return role, revision, found, nil
	}
	if !found {
		revision, err = projectRoleDefinitionRevision(project)
		return project, revision, true, err
	}
	if !role.ProjectPermissionOverride {
		role.Permissions = project.Permissions
	}
	return role, revision, true, nil
}

func (s *MetadataApplicationService) IdentityRoleFieldPermissionDefinition(ctx context.Context, roleKey string, principal identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	role, revision, found, err := s.identityRoleDefinitionForAction(ctx, roleKey, identitycontract.IdentityActionRoleFieldPermissionsList, false, principal)
	if err != nil {
		return role, revision, found, err
	}
	if found {
		if project, isProject := s.projectRoleDefinition(roleKey); isProject && !role.ProjectFieldPermissionOverride {
			role.FieldPermissions = project.FieldPermissions
		}
		return role, revision, true, nil
	}
	projectRole, found := s.projectRoleDefinition(roleKey)
	if !found {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, nil
	}
	revision, err = projectRoleDefinitionRevision(projectRole)
	if err != nil {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, metadataInternalErrorWithCause("hash project role field permission definition", err)
	}
	return projectRole, revision, true, nil
}

func (s *MetadataApplicationService) CreateIdentityRoleDefinition(ctx context.Context, role identitymodel.RoleSchema, businessReason, operationID string, principal identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error) {
	if err := authorizeIdentityRoleAction(principal, identitycontract.IdentityActionRolesCreate, true); err != nil {
		return identitymodel.IdentityRoleDefinitionRevision{}, err
	}
	return s.publishIdentityRoleDefinition(ctx, role, "", businessReason, operationID, "identity_role.created", "Created role "+strings.TrimSpace(role.Key), map[string]any{"change_kind": "create"}, true, principal)
}

func (s *MetadataApplicationService) UpdateIdentityRoleDefinition(ctx context.Context, roleKey string, request identitymodel.IdentityRoleDefinitionUpdateRequest, principal identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, error) {
	role, _, found, err := s.identityRoleDefinitionForAction(ctx, roleKey, identitycontract.IdentityActionRolesUpdate, true, principal)
	if err != nil {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, err
	}
	if !found {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, notFound("backend.identity.role_definition_not_found", "role", strings.TrimSpace(roleKey))
	}
	role.Name = strings.TrimSpace(request.Name)
	role.Description = strings.TrimSpace(request.Description)
	role.I18n = request.I18n
	revision, err := s.publishIdentityRoleDefinition(ctx, role, request.ExpectedSchemaHash, request.BusinessReason, request.OperationID, "identity_role.updated", "Updated role "+role.Key, map[string]any{"change_kind": "update"}, false, principal)
	if err != nil {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, err
	}
	return role, revision, nil
}

func (s *MetadataApplicationService) PublishIdentityRolePermissions(ctx context.Context, roleKey string, permissions []identitymodel.RolePermission, expectedSchemaHash, businessReason, operationID string, principal identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error) {
	role, _, found, err := s.identityRoleDefinitionForAction(ctx, roleKey, identitycontract.IdentityActionRolePermissionsPublish, true, principal)
	if err != nil {
		return identitymodel.IdentityRoleDefinitionRevision{}, err
	}
	if project, isProject := s.projectRoleDefinition(roleKey); isProject {
		if !found {
			revision, err := projectRoleDefinitionRevision(project)
			if err != nil {
				return identitymodel.IdentityRoleDefinitionRevision{}, err
			}
			if strings.TrimSpace(expectedSchemaHash) != revision.SchemaHash {
				return identitymodel.IdentityRoleDefinitionRevision{}, conflict("backend.metadata.definition_revision_conflict", "role", roleKey)
			}
			role = identitymodel.RoleSchema{Key: project.Key, Name: project.Name}
			expectedSchemaHash = ""
		}
		role.Permissions = append([]identitymodel.RolePermission(nil), permissions...)
		role.ProjectPermissionOverride = true
		return s.publishIdentityRoleDefinition(ctx, role, expectedSchemaHash, businessReason, operationID, "identity_role_permissions.published", "Published role permissions for "+role.Key, map[string]any{"permission_count": len(permissions), "project_role_overlay": true}, !found, principal)
	}
	if !found {
		return identitymodel.IdentityRoleDefinitionRevision{}, notFound("backend.identity.role_definition_not_found", "role", strings.TrimSpace(roleKey))
	}
	role.Permissions = append([]identitymodel.RolePermission(nil), permissions...)
	return s.publishIdentityRoleDefinition(ctx, role, expectedSchemaHash, businessReason, operationID, "identity_role_permissions.published", "Published role permissions for "+role.Key, map[string]any{"permission_count": len(role.Permissions)}, false, principal)
}

func (s *MetadataApplicationService) PublishIdentityRoleFieldPermissions(ctx context.Context, roleKey string, permissions []identitymodel.FieldPermission, expectedSchemaHash, businessReason, operationID string, principal identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error) {
	role, _, found, err := s.identityRoleDefinitionForAction(ctx, roleKey, identitycontract.IdentityActionRoleFieldPermissionsPublish, true, principal)
	if err != nil {
		return identitymodel.IdentityRoleDefinitionRevision{}, err
	}
	if !found {
		role, found = s.projectRoleDefinition(roleKey)
		if !found {
			return identitymodel.IdentityRoleDefinitionRevision{}, notFound("backend.identity.role_definition_not_found", "role", strings.TrimSpace(roleKey))
		}
		revision, revisionErr := projectRoleDefinitionRevision(role)
		if revisionErr != nil {
			return identitymodel.IdentityRoleDefinitionRevision{}, metadataInternalErrorWithCause("hash project role field permission definition", revisionErr)
		}
		if strings.TrimSpace(expectedSchemaHash) != revision.SchemaHash {
			return identitymodel.IdentityRoleDefinitionRevision{}, conflict("backend.metadata.definition_revision_conflict", "resource_type", "role", "resource_key", strings.TrimSpace(roleKey), "expected_hash", strings.TrimSpace(expectedSchemaHash), "current_hash", revision.SchemaHash)
		}
		overlay := identitymodel.RoleSchema{
			Key:                            strings.TrimSpace(role.Key),
			Name:                           strings.TrimSpace(role.Name),
			FieldPermissions:               append([]identitymodel.FieldPermission(nil), permissions...),
			ProjectFieldPermissionOverride: true,
		}
		return s.publishIdentityRoleDefinition(ctx, overlay, "", businessReason, operationID, "identity_role_field_permissions.published", "Published role field permissions for "+overlay.Key, map[string]any{"field_permission_count": len(overlay.FieldPermissions), "project_role_overlay": true}, true, principal)
	}
	role.FieldPermissions = append([]identitymodel.FieldPermission(nil), permissions...)
	if _, isProject := s.projectRoleDefinition(roleKey); isProject {
		role.ProjectFieldPermissionOverride = true
	}
	return s.publishIdentityRoleDefinition(ctx, role, expectedSchemaHash, businessReason, operationID, "identity_role_field_permissions.published", "Published role field permissions for "+role.Key, map[string]any{"field_permission_count": len(role.FieldPermissions)}, false, principal)
}

type metadataProjectRoleRuntime interface {
	ProjectRoleDefinition(string) (identitymodel.RoleSchema, bool)
}

func (s *MetadataApplicationService) projectRoleDefinition(roleKey string) (identitymodel.RoleSchema, bool) {
	runtime, ok := s.runtime.(metadataProjectRoleRuntime)
	if !ok {
		return identitymodel.RoleSchema{}, false
	}
	return runtime.ProjectRoleDefinition(strings.TrimSpace(roleKey))
}

func projectRoleDefinitionRevision(role identitymodel.RoleSchema) (identitymodel.IdentityRoleDefinitionRevision, error) {
	payload, err := json.Marshal(role)
	if err != nil {
		return identitymodel.IdentityRoleDefinitionRevision{}, err
	}
	digest := sha256.Sum256(payload)
	return identitymodel.IdentityRoleDefinitionRevision{SchemaVersion: "project", SchemaHash: fmt.Sprintf("%x", digest[:])}, nil
}

func (s *MetadataApplicationService) DisableIdentityRoleDefinition(ctx context.Context, roleKey, expectedSchemaHash, businessReason, operationID string, principal identitymodel.Principal) error {
	if err := authorizeIdentityRoleAction(principal, identitycontract.IdentityActionRolesDelete, true); err != nil {
		return err
	}
	roleKey, expectedSchemaHash = strings.TrimSpace(roleKey), strings.TrimSpace(expectedSchemaHash)
	businessReason, operationID = strings.TrimSpace(businessReason), strings.TrimSpace(operationID)
	if roleKey == "" {
		return badRequest("backend.identity.role_key_required")
	}
	if expectedSchemaHash == "" {
		return badRequest("backend.metadata.expected_schema_hash_required")
	}
	if businessReason == "" {
		return badRequest("backend.identity.role_business_reason_required")
	}
	if operationID == "" {
		return badRequest(idempotency.ErrorCodeMissingKey)
	}
	before, found, err := s.repository.GetDefinition(ctx, metadataInstallationScope("load Identity role definition for disable"), "role", roleKey)
	if err != nil {
		return wrapMetadataError(err)
	}
	if !found {
		return notFound("backend.identity.role_definition_not_found", "role", roleKey)
	}
	if s.audit == nil {
		return metadataInternalError("build Identity role disable audit")
	}
	audit := s.audit.NewAuditEvent(ctx, auditcontract.AuditAppendRequest{
		Family: auditmodel.EventFamilyIdentityGovernance, Event: "identity_role.deleted", ObjectKey: "role", RecordID: roleKey, Principal: principal,
		Summary: "Deleted role " + roleKey, Before: DefinitionAuditValue(before, true),
		After: map[string]any{"role_key": roleKey, "disabled": true}, Metadata: map[string]any{"business_reason": businessReason, "operation_id": operationID},
	})
	if err := s.repository.DisableDefinition(ctx, metadataInstallationScope("disable Identity role definition"), "role", roleKey, expectedSchemaHash, audit, metadataPublicationForPrincipal(principal)); err != nil {
		return wrapMetadataError(err)
	}
	if _, err := s.reloadMetadata(ctx); err != nil {
		return err
	}
	return nil
}

func (s *MetadataApplicationService) identityRoleDefinitionForAction(ctx context.Context, roleKey, actionKey string, command bool, principal identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	if err := authorizeIdentityRoleAction(principal, actionKey, command); err != nil {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, err
	}
	roleKey = strings.TrimSpace(roleKey)
	definition, found, err := s.repository.GetDefinition(ctx, metadataInstallationScope("load Identity role definition"), "role", roleKey)
	if err != nil {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, wrapMetadataError(err)
	}
	if !found {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, nil
	}
	var role identitymodel.RoleSchema
	if err := json.Unmarshal(definition.Payload, &role); err != nil {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, metadataInternalErrorWithCause("decode Identity role definition", err)
	}
	if strings.TrimSpace(role.Key) != roleKey {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, metadataInternalError("verify Identity role definition key")
	}
	return role, identitymodel.IdentityRoleDefinitionRevision{SchemaVersion: definition.SchemaVersion, SchemaHash: definition.SchemaHash}, true, nil
}

func authorizeIdentityRoleAction(principal identitymodel.Principal, actionKey string, command bool) error {
	var err error
	if command {
		err = metadataAuthorizeCommand(principal)
	} else {
		err = metadataAuthorizeQuery(principal)
	}
	if err != nil {
		return err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, actionKey) {
		return forbidden("auth.permission_denied")
	}
	return nil
}

func (s *MetadataApplicationService) publishIdentityRoleDefinition(ctx context.Context, role identitymodel.RoleSchema, expectedSchemaHash, businessReason, operationID, event, summary string, eventMetadata map[string]any, allowCreate bool, principal identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error) {
	role.Key = strings.TrimSpace(role.Key)
	expectedSchemaHash, businessReason, operationID = strings.TrimSpace(expectedSchemaHash), strings.TrimSpace(businessReason), strings.TrimSpace(operationID)
	if role.Key == "" {
		return identitymodel.IdentityRoleDefinitionRevision{}, badRequest("backend.identity.role_key_required")
	}
	if !allowCreate && expectedSchemaHash == "" {
		return identitymodel.IdentityRoleDefinitionRevision{}, badRequest("backend.metadata.expected_schema_hash_required")
	}
	if businessReason == "" {
		return identitymodel.IdentityRoleDefinitionRevision{}, badRequest("backend.identity.role_business_reason_required")
	}
	if operationID == "" {
		return identitymodel.IdentityRoleDefinitionRevision{}, badRequest(idempotency.ErrorCodeMissingKey)
	}
	payload, err := json.Marshal(role)
	if err != nil {
		return identitymodel.IdentityRoleDefinitionRevision{}, metadataInternalErrorWithCause("encode Identity role definition", err)
	}
	request := metadatamodel.MetadataDefinitionUpsertRequest{
		SourceKind: "identity", SourceID: event + ":" + operationID,
		ExpectedSchemaHash: &expectedSchemaHash, Payload: payload,
	}
	metadata := map[string]any{"business_reason": businessReason, "operation_id": operationID}
	for key, value := range eventMetadata {
		metadata[key] = value
	}
	definition, _, err := s.upsertMetadataDefinition(ctx, "role", role.Key, request, principal, metadataDefinitionPublicationOptions{event: event, summary: summary, metadata: metadata})
	if err != nil {
		return identitymodel.IdentityRoleDefinitionRevision{}, err
	}
	return identitymodel.IdentityRoleDefinitionRevision{SchemaVersion: definition.SchemaVersion, SchemaHash: definition.SchemaHash}, nil
}
