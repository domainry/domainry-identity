package metadata

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/domainry/domainry-foundation/idempotency"
	auditcontract "github.com/domainry/domainry-identity/internal/application/auditbinding"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func (s *MetadataApplicationService) IdentityRolePermissionDefinition(ctx context.Context, roleKey string, principal identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	return s.identityRoleDefinitionForAction(ctx, roleKey, identitycontract.IdentityActionRolePermissionsList, false, principal)
}

func (s *MetadataApplicationService) IdentityRoleFieldPermissionDefinition(ctx context.Context, roleKey string, principal identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	return s.identityRoleDefinitionForAction(ctx, roleKey, identitycontract.IdentityActionRoleFieldPermissionsList, false, principal)
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
		return identitymodel.IdentityRoleDefinitionRevision{}, notFound("backend.identity.role_definition_not_found", "role", strings.TrimSpace(roleKey))
	}
	role.FieldPermissions = append([]identitymodel.FieldPermission(nil), permissions...)
	return s.publishIdentityRoleDefinition(ctx, role, expectedSchemaHash, businessReason, operationID, "identity_role_field_permissions.published", "Published role field permissions for "+role.Key, map[string]any{"field_permission_count": len(role.FieldPermissions)}, false, principal)
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
		Event: "identity_role.deleted", ObjectKey: "role", RecordID: roleKey, Principal: principal,
		Summary: "Deleted role " + roleKey, Before: DefinitionAuditValue(before, true),
		After: map[string]any{"role_key": roleKey, "disabled": true}, Metadata: map[string]any{"business_reason": businessReason, "operation_id": operationID},
	})
	if err := s.repository.DisableDefinition(ctx, metadataInstallationScope("disable Identity role definition"), "role", roleKey, expectedSchemaHash, audit, metadataPublicationForPrincipal(principal)); err != nil {
		return wrapMetadataError(err)
	}
	if _, err := s.ReloadMetadata(ctx, principal); err != nil {
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
