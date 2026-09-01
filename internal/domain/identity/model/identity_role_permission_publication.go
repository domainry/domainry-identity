package identitymodel

// IdentityRoleDefinitionRevision identifies the current versioned RoleSchema
// definition used for optimistic concurrency at the administration boundary.
type IdentityRoleDefinitionRevision struct {
	SchemaVersion string `json:"schema_version"`
	SchemaHash    string `json:"schema_hash"`
}

type IdentityRolePermissionPublicationRequest struct {
	PermissionKeys     []string `json:"permission_keys"`
	ExpectedSchemaHash string   `json:"-"`
	BusinessReason     string   `json:"business_reason"`
	OperationID        string   `json:"-"`
}

type IdentityRolePermissionConfiguration struct {
	RoleID        string                             `json:"role_id"`
	RoleKey       string                             `json:"role_key"`
	Permissions   []IdentityRolePermissionAssignment `json:"permissions"`
	SchemaVersion string                             `json:"schema_version"`
	SchemaHash    string                             `json:"schema_hash"`
}
