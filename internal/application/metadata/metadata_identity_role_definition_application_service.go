package metadata

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/domainry/domainry-foundation/idempotency"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

// IdentityRoleDefinition exposes only the current RoleSchema and its CAS
// revision. It does not expose generic metadata authoring to the Identity HTTP
// adapter.
func (s *MetadataApplicationService) IdentityRoleDefinition(ctx context.Context, roleKey string, principal identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	if err := metadataAuthorizeQuery(principal); err != nil {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, "identity.permissions.read") && !identitycontract.IdentityRoleHasPermissionKey(principal.Role, "identity.permissions.write") {
		return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, forbidden("auth.permission_denied")
	}
	roleKey = strings.TrimSpace(roleKey)
	definition, found, err := s.repository.GetDefinition(ctx, metadataInstallationScope("load Identity role permission configuration"), "role", roleKey)
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

// PublishIdentityRolePermissions creates one normal RoleSchema version while
// preserving every field outside Permissions. The existing metadata store
// supplies CAS, idempotent replay, audit, directory projection, and reload.
func (s *MetadataApplicationService) PublishIdentityRolePermissions(ctx context.Context, role identitymodel.RoleSchema, expectedSchemaHash, businessReason, operationID string, principal identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error) {
	if err := metadataAuthorizeCommand(principal); err != nil {
		return identitymodel.IdentityRoleDefinitionRevision{}, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, "identity.permissions.write") {
		return identitymodel.IdentityRoleDefinitionRevision{}, forbidden("auth.permission_denied")
	}
	expectedSchemaHash = strings.TrimSpace(expectedSchemaHash)
	businessReason = strings.TrimSpace(businessReason)
	operationID = strings.TrimSpace(operationID)
	role.Key = strings.TrimSpace(role.Key)
	if role.Key == "" {
		return identitymodel.IdentityRoleDefinitionRevision{}, badRequest("backend.identity.role_key_required")
	}
	if expectedSchemaHash == "" {
		return identitymodel.IdentityRoleDefinitionRevision{}, badRequest("backend.metadata.expected_schema_hash_required")
	}
	if businessReason == "" {
		return identitymodel.IdentityRoleDefinitionRevision{}, badRequest("backend.identity.role_permission_business_reason_required")
	}
	if operationID == "" {
		return identitymodel.IdentityRoleDefinitionRevision{}, badRequest(idempotency.ErrorCodeMissingKey)
	}
	payload, err := json.Marshal(role)
	if err != nil {
		return identitymodel.IdentityRoleDefinitionRevision{}, metadataInternalErrorWithCause("encode Identity role definition", err)
	}
	request := metadatamodel.MetadataDefinitionUpsertRequest{
		SourceKind: "admin", SourceID: "identity-role-permissions:" + operationID,
		ExpectedSchemaHash: &expectedSchemaHash, Payload: payload,
	}
	definition, _, err := s.upsertMetadataDefinition(ctx, "role", role.Key, request, principal, metadataDefinitionPublicationOptions{
		event: "identity_role_permissions.published", summary: "Published role permissions for " + role.Key,
		metadata: map[string]any{"business_reason": businessReason, "operation_id": operationID, "permission_count": len(role.Permissions)},
	})
	if err != nil {
		return identitymodel.IdentityRoleDefinitionRevision{}, err
	}
	return identitymodel.IdentityRoleDefinitionRevision{SchemaVersion: definition.SchemaVersion, SchemaHash: definition.SchemaHash}, nil
}
