package identity

import (
	"context"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// IdentityRoleDefinitionPublisher is Identity's narrow port to the existing
// versioned RoleSchema store. Each method owns one exact authorization action;
// no command is allowed to acquire an unrelated list permission while loading
// the aggregate it changes.
type IdentityRoleDefinitionPublisher interface {
	IdentityRolePermissionDefinition(context.Context, string, identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error)
	IdentityRoleFieldPermissionDefinition(context.Context, string, identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error)
	CreateIdentityRoleDefinition(context.Context, identitymodel.RoleSchema, string, string, identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error)
	UpdateIdentityRoleDefinition(context.Context, string, identitymodel.IdentityRoleDefinitionUpdateRequest, identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, error)
	DisableIdentityRoleDefinition(context.Context, string, string, string, string, identitymodel.Principal) error
	PublishIdentityRolePermissions(context.Context, string, []identitymodel.RolePermission, string, string, string, identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error)
	PublishIdentityRoleFieldPermissions(context.Context, string, []identitymodel.FieldPermission, string, string, string, identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error)
}

// IdentityRoleDefinitionPublicationService is the single application boundary
// for direct RoleSchema authoring. RoleSchema remains the only authority for
// functional, data, and field grants.
type IdentityRoleDefinitionPublicationService struct {
	identity    *IdentityApplicationService
	permissions *IdentityPermissionCatalogApplicationService
	definitions IdentityRoleDefinitionPublisher
}

func NewIdentityRoleDefinitionPublicationService(identity *IdentityApplicationService, permissions *IdentityPermissionCatalogApplicationService, definitions IdentityRoleDefinitionPublisher) *IdentityRoleDefinitionPublicationService {
	return &IdentityRoleDefinitionPublicationService{identity: identity, permissions: permissions, definitions: definitions}
}

func (service *IdentityRoleDefinitionPublicationService) PermissionConfiguration(ctx context.Context, roleID string, principal identitymodel.Principal) (identitymodel.IdentityRolePermissionConfiguration, error) {
	role, err := service.operationalRole(ctx, roleID)
	if err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, err
	}
	definition, revision, found, err := service.definitions.IdentityRolePermissionDefinition(ctx, role.Key, principal)
	if err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, err
	}
	if !found {
		return identitymodel.IdentityRolePermissionConfiguration{}, roleDefinitionNotFound(role.Key)
	}
	return rolePermissionConfiguration(role, definition.Permissions, revision), nil
}

func (service *IdentityRoleDefinitionPublicationService) PublishPermissions(ctx context.Context, roleID string, request identitymodel.IdentityRolePermissionPublicationRequest, principal identitymodel.Principal) (identitymodel.IdentityRolePermissionConfiguration, error) {
	if err := validateRolePublicationCommand(request.ExpectedSchemaHash, request.BusinessReason, request.OperationID); err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, err
	}
	role, err := service.operationalRole(ctx, roleID)
	if err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, err
	}
	if service.permissions == nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, rolePublicationUnavailable()
	}
	requested, valid := identitymodel.NormalizeRolePermissions(request.Permissions)
	if !valid {
		return identitymodel.IdentityRolePermissionConfiguration{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_permission_invalid"}
	}
	if err := service.permissions.ValidatePermissionSelections(identitymodel.RolePermissionKeys(requested)); err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, err
	}
	revision, err := service.definitions.PublishIdentityRolePermissions(ctx, role.Key, requested, strings.TrimSpace(request.ExpectedSchemaHash), strings.TrimSpace(request.BusinessReason), strings.TrimSpace(request.OperationID), principal)
	if err != nil {
		return identitymodel.IdentityRolePermissionConfiguration{}, err
	}
	return rolePermissionConfiguration(role, requested, revision), nil
}

func (service *IdentityRoleDefinitionPublicationService) FieldPermissionConfiguration(ctx context.Context, roleID string, principal identitymodel.Principal) (identitymodel.IdentityRoleFieldPermissionConfiguration, error) {
	role, err := service.operationalRole(ctx, roleID)
	if err != nil {
		return identitymodel.IdentityRoleFieldPermissionConfiguration{}, err
	}
	definition, revision, found, err := service.definitions.IdentityRoleFieldPermissionDefinition(ctx, role.Key, principal)
	if err != nil {
		return identitymodel.IdentityRoleFieldPermissionConfiguration{}, err
	}
	if !found {
		return identitymodel.IdentityRoleFieldPermissionConfiguration{}, roleDefinitionNotFound(role.Key)
	}
	return roleFieldPermissionConfiguration(role, definition.FieldPermissions, revision), nil
}

func (service *IdentityRoleDefinitionPublicationService) PublishFieldPermissions(ctx context.Context, roleID string, request identitymodel.IdentityRoleFieldPermissionPublicationRequest, principal identitymodel.Principal) (identitymodel.IdentityRoleFieldPermissionConfiguration, error) {
	if err := validateRolePublicationCommand(request.ExpectedSchemaHash, request.BusinessReason, request.OperationID); err != nil {
		return identitymodel.IdentityRoleFieldPermissionConfiguration{}, err
	}
	role, err := service.operationalRole(ctx, roleID)
	if err != nil {
		return identitymodel.IdentityRoleFieldPermissionConfiguration{}, err
	}
	fieldPermissions, err := normalizedFieldPermissions(request.FieldPermissions)
	if err != nil {
		return identitymodel.IdentityRoleFieldPermissionConfiguration{}, err
	}
	revision, err := service.definitions.PublishIdentityRoleFieldPermissions(ctx, role.Key, fieldPermissions, strings.TrimSpace(request.ExpectedSchemaHash), strings.TrimSpace(request.BusinessReason), strings.TrimSpace(request.OperationID), principal)
	if err != nil {
		return identitymodel.IdentityRoleFieldPermissionConfiguration{}, err
	}
	return roleFieldPermissionConfiguration(role, fieldPermissions, revision), nil
}

func (service *IdentityRoleDefinitionPublicationService) Create(ctx context.Context, request identitymodel.IdentityRoleDefinitionMutationRequest, principal identitymodel.Principal) (identitymodel.IdentityRoleDefinitionConfiguration, error) {
	if err := validateRoleCreateCommand(request.BusinessReason, request.OperationID); err != nil {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, err
	}
	definition, err := normalizeNewRoleDefinition(request.Role)
	if err != nil {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, err
	}
	if definition.Key == "" {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_key_required"}
	}
	if definition.Name == "" {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_name_required"}
	}
	if service == nil || service.permissions == nil || service.definitions == nil {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, rolePublicationUnavailable()
	}
	if err := service.permissions.ValidatePermissionSelections(identitymodel.RolePermissionKeys(definition.Permissions)); err != nil {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, err
	}
	revision, err := service.definitions.CreateIdentityRoleDefinition(ctx, definition, strings.TrimSpace(request.BusinessReason), strings.TrimSpace(request.OperationID), principal)
	if err != nil {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, err
	}
	return identitymodel.IdentityRoleDefinitionConfiguration{Role: definition, SchemaVersion: revision.SchemaVersion, SchemaHash: revision.SchemaHash}, nil
}

func (service *IdentityRoleDefinitionPublicationService) Update(ctx context.Context, roleID string, request identitymodel.IdentityRoleDefinitionUpdateRequest, principal identitymodel.Principal) (identitymodel.IdentityRoleDefinitionConfiguration, error) {
	if err := validateRolePublicationCommand(request.ExpectedSchemaHash, request.BusinessReason, request.OperationID); err != nil {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, err
	}
	role, err := service.operationalRole(ctx, roleID)
	if err != nil {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, err
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Description = strings.TrimSpace(request.Description)
	if request.Name == "" {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_name_required"}
	}
	definition, revision, err := service.definitions.UpdateIdentityRoleDefinition(ctx, role.Key, request, principal)
	if err != nil {
		return identitymodel.IdentityRoleDefinitionConfiguration{}, err
	}
	return identitymodel.IdentityRoleDefinitionConfiguration{Role: definition, SchemaVersion: revision.SchemaVersion, SchemaHash: revision.SchemaHash}, nil
}

func (service *IdentityRoleDefinitionPublicationService) Delete(ctx context.Context, roleID string, request identitymodel.IdentityRoleDefinitionDeleteRequest, principal identitymodel.Principal) error {
	if err := validateRolePublicationCommand(request.ExpectedSchemaHash, request.BusinessReason, request.OperationID); err != nil {
		return err
	}
	role, err := service.operationalRole(ctx, roleID)
	if err != nil {
		return err
	}
	assignments, err := service.identity.ListUserRoleAssignments(ctx, "")
	if err != nil {
		return err
	}
	for _, assignment := range assignments {
		if strings.TrimSpace(assignment.RoleID) == role.ID || strings.TrimSpace(assignment.RoleID) == role.Key {
			return &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.role_has_assignments", Params: map[string]string{"role": role.Key}}
		}
	}
	menus, err := service.identity.ListRoleMenuAssignments(ctx, role.ID)
	if err != nil {
		return err
	}
	if len(menus) != 0 {
		return &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.role_has_menu_assignments", Params: map[string]string{"role": role.Key}}
	}
	return service.definitions.DisableIdentityRoleDefinition(ctx, role.Key, strings.TrimSpace(request.ExpectedSchemaHash), strings.TrimSpace(request.BusinessReason), strings.TrimSpace(request.OperationID), principal)
}

func (service *IdentityRoleDefinitionPublicationService) operationalRole(ctx context.Context, roleID string) (identitymodel.IdentityRole, error) {
	roleID = strings.TrimSpace(roleID)
	if service == nil || service.identity == nil || service.definitions == nil {
		return identitymodel.IdentityRole{}, rolePublicationUnavailable()
	}
	role, found, err := service.identity.RoleByID(ctx, roleID)
	if err != nil {
		return identitymodel.IdentityRole{}, err
	}
	if !found {
		return identitymodel.IdentityRole{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.role_not_found", Params: map[string]string{"role": roleID}}
	}
	return role, nil
}

func validateRoleCreateCommand(businessReason, operationID string) error {
	if strings.TrimSpace(businessReason) == "" {
		return &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_business_reason_required"}
	}
	if strings.TrimSpace(operationID) == "" {
		return &apperror.AppError{Kind: apperror.KindBadRequest, Code: idempotency.ErrorCodeMissingKey}
	}
	return nil
}

func validateRolePublicationCommand(expectedSchemaHash, businessReason, operationID string) error {
	if strings.TrimSpace(expectedSchemaHash) == "" {
		return &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.metadata.expected_schema_hash_required"}
	}
	return validateRoleCreateCommand(businessReason, operationID)
}

func normalizeNewRoleDefinition(role identitymodel.RoleSchema) (identitymodel.RoleSchema, error) {
	role.Key = strings.ToLower(strings.TrimSpace(role.Key))
	role.Name = strings.TrimSpace(role.Name)
	role.Description = strings.TrimSpace(role.Description)
	permissions, valid := identitymodel.NormalizeRolePermissions(role.Permissions)
	if !valid {
		return identitymodel.RoleSchema{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_permission_invalid"}
	}
	role.Permissions = permissions
	role.FieldPermissions = nil
	role.ReferencePermissions = nil
	role.ExportRules = nil
	role.ConflictRoleKeys = nil
	role.GrantableRoleKeys = nil
	role.PermissionSetKeys = nil
	role.PermissionSetGroups = nil
	role.GuardrailKeys = nil
	role.Guardrails = nil
	role.ProvisionToWorkspaces = false
	if role.Audience == "" {
		role.Audience = identitymodel.IdentityRoleAudienceAny
	}
	if role.AssignmentMode == "" {
		role.AssignmentMode = identitymodel.IdentityRoleAssignmentManual
	}
	if role.RiskLevel == "" {
		role.RiskLevel = identitymodel.IdentityRoleRiskNormal
	}
	return role, nil
}

func normalizedFieldPermissions(values []identitymodel.IdentityFieldPermission) ([]identitymodel.FieldPermission, error) {
	byField := make(map[string]identitymodel.FieldPermission, len(values))
	for _, value := range values {
		resource, field := strings.TrimSpace(value.Resource), strings.TrimSpace(value.Field)
		if resource == "" || field == "" {
			return nil, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_field_permission_invalid"}
		}
		key := resource + "\x00" + field
		if _, duplicate := byField[key]; duplicate {
			return nil, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_field_permission_duplicate", Params: map[string]string{"resource": resource, "field": field}}
		}
		visible, editable := value.Visible, value.Editable
		if editable {
			visible = true
		}
		byField[key] = identitymodel.FieldPermission{ObjectKey: resource, FieldKey: field, Read: visible, Write: editable, Export: visible, Masked: value.Masked, Policies: value.Policies}
	}
	keys := make([]string, 0, len(byField))
	for key := range byField {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]identitymodel.FieldPermission, 0, len(keys))
	for _, key := range keys {
		out = append(out, byField[key])
	}
	return out, nil
}

func rolePermissionConfiguration(role identitymodel.IdentityRole, permissions []identitymodel.RolePermission, revision identitymodel.IdentityRoleDefinitionRevision) identitymodel.IdentityRolePermissionConfiguration {
	assignments := make([]identitymodel.IdentityRolePermissionAssignment, 0, len(permissions))
	normalized, _ := identitymodel.NormalizeRolePermissions(permissions)
	for _, permission := range normalized {
		assignments = append(assignments, identitymodel.IdentityRolePermissionAssignment{RoleID: role.ID, PermissionKey: permission.PermissionKey, DataScope: permission.DataScope, AuditDenial: permission.AuditDenial})
	}
	return identitymodel.IdentityRolePermissionConfiguration{RoleID: role.ID, RoleKey: role.Key, Permissions: assignments, SchemaVersion: revision.SchemaVersion, SchemaHash: revision.SchemaHash}
}

func roleFieldPermissionConfiguration(role identitymodel.IdentityRole, values []identitymodel.FieldPermission, revision identitymodel.IdentityRoleDefinitionRevision) identitymodel.IdentityRoleFieldPermissionConfiguration {
	permissions := make([]identitymodel.IdentityFieldPermission, 0, len(values))
	for _, value := range values {
		if resource, field := strings.TrimSpace(value.ObjectKey), strings.TrimSpace(value.FieldKey); resource != "" && field != "" {
			permissions = append(permissions, identitymodel.IdentityFieldPermission{Resource: resource, Field: field, Visible: value.Read, Editable: value.Write, Masked: value.Masked, Policies: value.Policies})
		}
	}
	return identitymodel.IdentityRoleFieldPermissionConfiguration{RoleID: role.ID, RoleKey: role.Key, FieldPermissions: permissions, SchemaVersion: revision.SchemaVersion, SchemaHash: revision.SchemaHash}
}

func rolePublicationUnavailable() error {
	return &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.role_definition_publication_unavailable"}
}

func roleDefinitionNotFound(roleKey string) error {
	return &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.role_definition_not_found", Params: map[string]string{"role": roleKey}}
}
