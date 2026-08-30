package contract

import (
	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
)

func IdentityRoleAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed, open := identityBoolPointer(false), identityBoolPointer(true)
	stringList := authoringcontract.CapabilityAuthoringSchema{Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Type: "string", MinLength: identityIntPointer(1)}}
	openList := authoringcontract.CapabilityAuthoringSchema{Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: open}}
	payload := authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: closed,
		Required: []string{"key", "name", "permissions", "record_scope"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"key": {Type: "string", MinLength: identityIntPointer(1)}, "name": {Type: "string", MinLength: identityIntPointer(1)},
			"i18n": {Type: "object", AdditionalProperties: open}, "permissions": stringList, "record_scope": {Type: "string", MinLength: identityIntPointer(1)},
			"data_permissions": openList, "field_permissions": openList, "reference_permissions": openList, "export_rules": openList,
			"audience":             {Type: "string", Enum: []any{"any", "workforce", "business_profile", "service"}, Default: "any"},
			"required_binding_key": {Type: "string"}, "assignment_mode": {Type: "string", Enum: []any{"manual", "request_only", "system_managed"}, Default: "manual"},
			"risk_level":         {Type: "string", Enum: []any{"normal", "elevated", "privileged"}, Default: "normal"},
			"conflict_role_keys": stringList, "grantable_role_keys": stringList,
			"permission_set_keys": stringList, "permission_set_group_keys": stringList, "guardrail_keys": stringList,
		},
	}
	input := metadatacontract.VersionedMetadataDefinitionRequestSchema(payload, false)
	output := metadatacontract.VersionedMetadataDefinitionOutputSchema(payload)
	execution := metadatacontract.VersionedMetadataDefinitionExecution("identity.role")
	execution.PermissionModel = "identity.roles.write"
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.role", Status: "supported", Lifecycle: "versioned_metadata",
		Parameters: []authoringcontract.CapabilityAuthoringParameter{
			{Key: "key", Type: "string", Required: true}, {Key: "name", Type: "string", Required: true}, {Key: "permissions", Type: "array", Required: true, ItemSchema: "permission_key"},
			{Key: "record_scope", Type: "string", Required: true}, {Key: "expected_schema_hash", Type: "schema_hash", Required: true},
			{Key: "audience", Type: "string", Default: "any", Enum: []string{"any", "workforce", "business_profile", "service"}},
			{Key: "required_binding_key", Type: "string"}, {Key: "assignment_mode", Type: "string", Default: "manual", Enum: []string{"manual", "request_only", "system_managed"}},
			{Key: "risk_level", Type: "string", Default: "normal", Enum: []string{"normal", "elevated", "privileged"}},
			{Key: "permission_set_keys", Type: "array", ItemSchema: "permission_set_key"},
			{Key: "permission_set_group_keys", Type: "array", ItemSchema: "permission_set_group_key"},
			{Key: "guardrail_keys", Type: "array", ItemSchema: "guardrail_key"},
		},
		Permissions: []string{"identity.roles.write"}, AuditEvents: []string{"metadata_definition.saved"},
		ValidationEndpoint: "POST /tenant-admin/metadata/definitions/role/{resourceKey}/validate", ConfigurationRoutes: metadatacontract.VersionedMetadataDefinitionRoutes("role"),
		ResourceOperations:       metadatacontract.VersionedMetadataDefinitionOperations("role"),
		ResourceKeyPathParameter: "resourceKey", InputSchema: input, OutputSchema: output,
		OutputVariables: []authoringcontract.CapabilityAuthoringOutput{{Name: "role_id", JSONPointer: "/definition/resource_key", Type: "role_key", VisibleTo: "subsequent_capability_calls"}},
		Execution:       execution,
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.identity.role_id_key_required", FieldPath: "payload.key", MessageKey: "backend.identity.role_id_key_required"},
			{Code: "backend.identity.permission_not_found", FieldPath: "payload.permissions[]", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.permission_not_found"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"expected_schema_hash": "$instance.schema_hash", "payload": map[string]any{"key": "sales_manager", "name": "Sales Manager", "permissions": []any{"order.read"}, "record_scope": "all_records"}}},
			{Name: "representative", Value: map[string]any{"expected_schema_hash": "$instance.schema_hash", "payload": map[string]any{"key": "sales_manager", "name": "Sales Manager", "permissions": []any{}, "record_scope": "none", "permission_set_group_keys": []any{"sales_operations"}, "guardrail_keys": []any{"protect_security_raw"}}}},
			{Name: "invalid_with_repair", Value: map[string]any{"expected_schema_hash": "$instance.schema_hash", "payload": map[string]any{"key": "", "name": "Sales Manager", "permissions": []any{}, "record_scope": "all_records"}}, ExpectedErrorCodes: []string{"backend.identity.role_id_key_required"}},
		},
		Sources: []authoringcontract.CapabilityAuthoringSource{{Kind: "model", Path: "internal/domain/identity/model/identity_manifest.go", Symbol: "RoleSchema"}, {Kind: "validation", Path: "internal/application/metadata/metadata_candidate_validation_application_service.go", Symbol: "ValidateMetadataCandidate"}, {Kind: "service", Path: "internal/application/metadata/metadata_application_service.go", Symbol: "UpsertMetadataDefinition"}},
	}
}

func IdentityRolePermissionAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed := identityBoolPointer(false)
	input := &authoringcontract.CapabilityAuthoringSchema{
		Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed, Required: []string{"permission_keys"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{"permission_keys": {Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Type: "string", MinLength: identityIntPointer(1)}}},
	}
	assignment := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Required: []string{"permission_key", "role_id"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{"role_id": {Type: "string"}, "permission_key": {Type: "string"}}}
	output := &authoringcontract.CapabilityAuthoringSchema{Schema: "https://json-schema.org/draft/2020-12/schema", Type: "array", Items: &assignment}
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.role_permission", Status: "supported", Lifecycle: "versioned_metadata", Requires: []string{"identity.role"},
		Parameters:  []authoringcontract.CapabilityAuthoringParameter{{Key: "permission_keys", Type: "array", Required: true, ItemSchema: "permission_key"}},
		Permissions: []string{"identity.permissions.write"}, AuditEvents: []string{"metadata_definition.saved"},
		ValidationEndpoint: "POST /identity/roles/{roleID}/permissions/validate", ConfigurationRoutes: identityRoleMetadataRoutes("POST /identity/roles/{roleID}/permissions/validate", "GET /identity/roles/{roleID}/permissions"),
		ResourceKeyPathParameter: "roleID", InputSchema: input, OutputSchema: output,
		OutputVariables: []authoringcontract.CapabilityAuthoringOutput{{Name: "permission_assignments", JSONPointer: "/", Type: "identity_role_permission_list", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{
			{Kind: "role_id", InputJSONPointer: "/@path/roleID", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/role_id"},
			{Kind: "permission_key", InputJSONPointer: "/permission_keys/*", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/permission_key"},
		},
		Execution: &authoringcontract.CapabilityAuthoringExecution{
			ReadSet: []string{"identity.role", "identity.permission_catalog"}, WriteSet: []string{"metadata.definition_version", "identity.role"}, Transaction: "metadata_repository_transaction", Idempotency: "builder_task_id_and_idempotency_key",
			SideEffects: []string{"audit:metadata_definition.saved", "schema_snapshot_rebuild"}, SideEffectLevel: "internal", Compensation: "restore_prior_version_as_new_revision", PermissionModel: "identity.permissions.write", ChangeControl: "direct_audited_versioned_metadata",
		},
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.identity.permission_not_found", FieldPath: "permission_keys[]", ParameterKeys: []string{"allowed", "actual"}, MessageKey: "backend.identity.permission_not_found"},
			{Code: "backend.identity.permission_duplicate", FieldPath: "permission_keys[]", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.permission_duplicate"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"permission_keys": []any{"order.complete"}}},
			{Name: "representative", Value: map[string]any{"permission_keys": []any{"order.complete", "order.read"}}},
			{Name: "invalid_with_repair", Value: map[string]any{"permission_keys": []any{"order.complete", "order.complete"}}, ExpectedErrorCodes: []string{"backend.identity.permission_duplicate"}},
		},
		Sources: identityAuthoringSources("IdentityPermissionDefinition", "ValidateRolePermissions"),
	}
}

func identityRoleMetadataRoutes(readRoutes ...string) []string {
	routes := append([]string(nil), readRoutes...)
	return append(routes,
		"GET /tenant-admin/metadata/definitions/role/{roleID}",
		"GET /tenant-admin/metadata/definitions/role/{roleID}/versions",
		"PUT /tenant-admin/metadata/definitions/role/{roleID}",
	)
}

func identityAuthoringSources(modelSymbol, validationSymbol string) []authoringcontract.CapabilityAuthoringSource {
	return []authoringcontract.CapabilityAuthoringSource{
		{Kind: "contract", Path: "internal/domain/identity/contract/identity_authoring.go"},
		{Kind: "model", Path: "internal/domain/identity/model/identity_model.go", Symbol: modelSymbol},
		{Kind: "validation", Path: "internal/application/identity/identity_governance_application_service.go", Symbol: validationSymbol},
		{Kind: "http", Path: "internal/transport/http/identity/identity_routes.go", Symbol: "RegisterRoutes"},
	}
}

func identityBoolPointer(value bool) *bool { return &value }
func identityIntPointer(value int) *int    { return &value }

func identityAuditedResourceOperations(validate, upsert, get, versions, deleteEndpoint string) *authoringcontract.CapabilityAuthoringResourceOperations {
	return &authoringcontract.CapabilityAuthoringResourceOperations{PersistenceMode: "audited_resource", Validate: validate, Upsert: upsert, UpsertHeaders: authoringcontract.DirectAuthoringUpsertHeaders(), SuccessSchema: authoringcontract.DirectAuthoringSuccessSchema(), Get: get, Versions: versions, Delete: deleteEndpoint}
}
