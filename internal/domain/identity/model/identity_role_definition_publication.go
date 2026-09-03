package identitymodel

import localizationmodel "github.com/domainry/domainry-identity/internal/domain/localization/model"

// IdentityRoleDefinitionRevision identifies the current versioned RoleSchema
// definition used for optimistic concurrency at the administration boundary.
type IdentityRoleDefinitionRevision struct {
	SchemaVersion string `json:"schema_version"`
	SchemaHash    string `json:"schema_hash"`
}

// IdentityRoleDefinitionMutationRequest is the direct, versioned role create
// command. OperationID is supplied by the Idempotency-Key header and
// ExpectedSchemaHash by Expected-Schema-Hash.
type IdentityRoleDefinitionMutationRequest struct {
	Role               RoleSchema `json:"role"`
	ExpectedSchemaHash string     `json:"-"`
	BusinessReason     string     `json:"business_reason"`
	OperationID        string     `json:"-"`
}

type IdentityRoleDefinitionConfiguration struct {
	Role          RoleSchema `json:"role"`
	SchemaVersion string     `json:"schema_version"`
	SchemaHash    string     `json:"schema_hash"`
}

type IdentityRoleDefinitionUpdateRequest struct {
	Name               string                             `json:"name"`
	Description        string                             `json:"description,omitempty"`
	I18n               localizationmodel.LocalizedTextMap `json:"i18n,omitempty"`
	ExpectedSchemaHash string                             `json:"-"`
	BusinessReason     string                             `json:"business_reason"`
	OperationID        string                             `json:"-"`
}

type IdentityRoleDefinitionDeleteRequest struct {
	ExpectedSchemaHash string `json:"-"`
	BusinessReason     string `json:"business_reason"`
	OperationID        string `json:"-"`
}

type IdentityRolePermissionPublicationRequest struct {
	Permissions        []RolePermission `json:"permissions"`
	ExpectedSchemaHash string           `json:"-"`
	BusinessReason     string           `json:"business_reason"`
	OperationID        string           `json:"-"`
}

type IdentityRolePermissionConfiguration struct {
	RoleID        string                             `json:"role_id"`
	RoleKey       string                             `json:"role_key"`
	Permissions   []IdentityRolePermissionAssignment `json:"permissions"`
	SchemaVersion string                             `json:"schema_version"`
	SchemaHash    string                             `json:"schema_hash"`
}

type IdentityRoleFieldPermissionPublicationRequest struct {
	FieldPermissions   []IdentityFieldPermission `json:"field_permissions"`
	ExpectedSchemaHash string                    `json:"-"`
	BusinessReason     string                    `json:"business_reason"`
	OperationID        string                    `json:"-"`
}

type IdentityRoleFieldPermissionConfiguration struct {
	RoleID           string                    `json:"role_id"`
	RoleKey          string                    `json:"role_key"`
	FieldPermissions []IdentityFieldPermission `json:"field_permissions"`
	SchemaVersion    string                    `json:"schema_version"`
	SchemaHash       string                    `json:"schema_hash"`
}
