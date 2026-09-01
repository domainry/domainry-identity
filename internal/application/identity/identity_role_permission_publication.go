package identity

import (
	"context"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// IdentityRoleDefinitionPublisher is the narrow RoleSchema version boundary
// required by Identity authorization authoring. The metadata application owns
// persistence, versioning, CAS, audit, and runtime reload behind this port.
type IdentityRoleDefinitionPublisher interface {
	IdentityRoleDefinition(context.Context, string, identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error)
	PublishIdentityRolePermissions(context.Context, identitymodel.RoleSchema, string, string, string, identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error)
}

type IdentityRolePermissionPublicationService struct {
	identity    *IdentityApplicationService
	permissions *IdentityPermissionCatalogApplicationService
	definitions IdentityRoleDefinitionPublisher
}

func NewIdentityRolePermissionPublicationService(identity *IdentityApplicationService, permissions *IdentityPermissionCatalogApplicationService, definitions IdentityRoleDefinitionPublisher) *IdentityRolePermissionPublicationService {
	return &IdentityRolePermissionPublicationService{identity: identity, permissions: permissions, definitions: definitions}
}

func (service *IdentityRolePermissionPublicationService) Configuration(ctx context.Context, roleID string, principal identitymodel.Principal) (identitymodel.IdentityRolePermissionConfiguration, error) {
	configuration, _, err := service.loadConfiguration(ctx, roleID, principal)
	return configuration, err
}

func (service *IdentityRolePermissionPublicationService) loadConfiguration(ctx context.Context, roleID string, principal identitymodel.Principal) (identitymodel.IdentityRolePermissionConfiguration, identitymodel.RoleSchema, error) {
	roleID = strings.TrimSpace(roleID)
	if service == nil || service.identity == nil || service.definitions == nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, identitymodel.RoleSchema{}, &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.role_definition_publication_unavailable"}
	}
	role, found, err := service.identity.RoleByID(ctx, roleID)
	if err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, identitymodel.RoleSchema{}, err
	}
	if !found {
		return identitymodel.IdentityRolePermissionConfiguration{}, identitymodel.RoleSchema{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.role_not_found", Params: map[string]string{"role": roleID}}
	}
	definition, revision, found, err := service.definitions.IdentityRoleDefinition(ctx, role.Key, principal)
	if err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, identitymodel.RoleSchema{}, err
	}
	if !found {
		return identitymodel.IdentityRolePermissionConfiguration{}, identitymodel.RoleSchema{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.role_definition_not_found", Params: map[string]string{"role": role.Key}}
	}
	permissions := make([]identitymodel.IdentityRolePermissionAssignment, 0, len(definition.Permissions))
	for _, key := range normalizedPermissionKeys(definition.Permissions) {
		permissions = append(permissions, identitymodel.IdentityRolePermissionAssignment{RoleID: role.ID, PermissionKey: key})
	}
	return identitymodel.IdentityRolePermissionConfiguration{
		RoleID: role.ID, RoleKey: role.Key, Permissions: permissions,
		SchemaVersion: revision.SchemaVersion, SchemaHash: revision.SchemaHash,
	}, definition, nil
}

func (service *IdentityRolePermissionPublicationService) Publish(ctx context.Context, roleID string, request identitymodel.IdentityRolePermissionPublicationRequest, principal identitymodel.Principal) (identitymodel.IdentityRolePermissionConfiguration, error) {
	request.ExpectedSchemaHash = strings.TrimSpace(request.ExpectedSchemaHash)
	request.BusinessReason = strings.TrimSpace(request.BusinessReason)
	request.OperationID = strings.TrimSpace(request.OperationID)
	if request.ExpectedSchemaHash == "" {
		return identitymodel.IdentityRolePermissionConfiguration{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.metadata.expected_schema_hash_required"}
	}
	if request.BusinessReason == "" {
		return identitymodel.IdentityRolePermissionConfiguration{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_permission_business_reason_required"}
	}
	if request.OperationID == "" {
		return identitymodel.IdentityRolePermissionConfiguration{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: idempotency.ErrorCodeMissingKey}
	}
	current, definition, err := service.loadConfiguration(ctx, roleID, principal)
	if err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, err
	}
	if service.permissions == nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.role_definition_publication_unavailable"}
	}
	requested := normalizedPermissionKeys(request.PermissionKeys)
	if err := service.permissions.ValidatePermissionSelections(requested); err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, err
	}
	definition.Permissions = requested
	revision, err := service.definitions.PublishIdentityRolePermissions(ctx, definition, request.ExpectedSchemaHash, request.BusinessReason, request.OperationID, principal)
	if err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, err
	}
	permissions := make([]identitymodel.IdentityRolePermissionAssignment, 0, len(requested))
	for _, key := range requested {
		permissions = append(permissions, identitymodel.IdentityRolePermissionAssignment{RoleID: current.RoleID, PermissionKey: key})
	}
	return identitymodel.IdentityRolePermissionConfiguration{
		RoleID: current.RoleID, RoleKey: current.RoleKey, Permissions: permissions,
		SchemaVersion: revision.SchemaVersion, SchemaHash: revision.SchemaHash,
	}, nil
}

func normalizedPermissionKeys(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
