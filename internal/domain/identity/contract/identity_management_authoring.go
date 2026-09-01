package contract

import (
	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
)

func IdentityUserAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed := identityBoolPointer(false)
	input := &authoringcontract.CapabilityAuthoringSchema{
		Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed,
		Required: []string{"id", "name", "email", "status"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"id": {Type: "string", MinLength: identityIntPointer(1)}, "name": {Type: "string", MinLength: identityIntPointer(1)}, "email": {Type: "string", Format: "email", MinLength: identityIntPointer(1)},
			"given_name": {Type: "string"}, "middle_name": {Type: "string"}, "family_name": {Type: "string"},
			"name_prefix": {Type: "string"}, "name_suffix": {Type: "string"}, "native_name": {Type: "string"}, "name_locale": {Type: "string"},
			"phone": {Type: "string"}, "account_type": {Type: "string", Enum: []any{"human", "service", "automation"}, Default: "human"},
			"locale": {Type: "string"}, "timezone": {Type: "string"}, "status": {Type: "string", Enum: []any{"active", "disabled"}},
		},
	}
	output := identityUserOutputSchema(closed)
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.user", Status: "supported", Lifecycle: "immediate_audited_configuration",
		Parameters: []authoringcontract.CapabilityAuthoringParameter{
			{Key: "id", Type: "string", Required: true}, {Key: "name", Type: "string", Required: true}, {Key: "email", Type: "string", Format: "email", Required: true},
			{Key: "given_name", Type: "string"}, {Key: "middle_name", Type: "string"}, {Key: "family_name", Type: "string"},
			{Key: "name_prefix", Type: "string"}, {Key: "name_suffix", Type: "string"}, {Key: "native_name", Type: "string"}, {Key: "name_locale", Type: "string"},
			{Key: "phone", Type: "string"}, {Key: "account_type", Type: "string", Default: "human", Enum: []string{"human", "service", "automation"}},
			{Key: "locale", Type: "string"}, {Key: "timezone", Type: "string"}, {Key: "status", Type: "string", Required: true, Enum: []string{"active", "disabled"}},
		},
		AuditEvents:        []string{"identity_user_created", "identity_user_updated"},
		ValidationEndpoint: "POST /identity/users/{userID}/validate", ConfigurationRoutes: []string{"POST /identity/users", "PATCH /identity/users/{userID}", "GET /identity/users/{userID}", "GET /identity/users/{userID}/versions", "DELETE /identity/users/{userID}", "POST /identity/users/{userID}/disable", "POST /identity/users/{userID}/enable"},
		ResourceOperations:       identityAuditedResourceOperations("POST /identity/users/{userID}/validate", "PATCH /identity/users/{userID}", "GET /identity/users/{userID}", "GET /identity/users/{userID}/versions", "DELETE /identity/users/{userID}"),
		ResourceKeyPathParameter: "userID", InputSchema: input, OutputSchema: output,
		OutputVariables: []authoringcontract.CapabilityAuthoringOutput{{Name: "user_id", JSONPointer: "/id", Type: "user_id", VisibleTo: "subsequent_capability_calls"}},
		Execution:       identityManagementExecution([]string{"identity.user"}, "identity.user", "stable_user_id_upsert", "identity_user_updated"),
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.identity.user_required", FieldPath: "id", MessageKey: "backend.identity.user_required"},
			{Code: "backend.identity.user_name_required", FieldPath: "name", MessageKey: "backend.identity.user_name_required"},
			{Code: "backend.identity.user_email_required", FieldPath: "email", MessageKey: "backend.identity.user_email_required"},
			{Code: "backend.identity.user_email_invalid", FieldPath: "email", ParameterKeys: []string{"actual", "expected"}, MessageKey: "backend.identity.user_email_invalid"},
			{Code: "backend.identity.user_email_exists", FieldPath: "email", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.user_email_exists"},
			{Code: "backend.identity.user_account_type_invalid", FieldPath: "account_type", ParameterKeys: []string{"actual", "allowed"}, MessageKey: "backend.identity.user_account_type_invalid"},
			{Code: "backend.identity.user_timezone_invalid", FieldPath: "timezone", ParameterKeys: []string{"actual", "expected"}, MessageKey: "backend.identity.user_timezone_invalid"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"id": "sales_rep", "name": "Sales Rep", "email": "sales.rep@example.com", "account_type": "human", "status": "active"}},
			{Name: "representative", Value: map[string]any{"id": "sales_rep", "name": "Dr. María José Carreño Quiñones", "given_name": "María", "middle_name": "José", "family_name": "Carreño Quiñones", "name_prefix": "Dr.", "native_name": "마리아 카레뇨", "name_locale": "es-CO", "email": "sales.rep@example.com", "phone": "+1-555-0100", "account_type": "human", "locale": "es-CO", "timezone": "America/Bogota", "status": "active"}},
			{Name: "invalid_with_repair", Value: map[string]any{"id": "sales_rep", "name": "Sales Rep", "email": "not-an-email", "status": "active"}, ExpectedErrorCodes: []string{"backend.identity.user_email_invalid"}},
		}, Sources: identityManagementAuthoringSources("IdentityUser", "ValidateUserConfiguration"),
	}
}

func IdentityDepartmentAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed := identityBoolPointer(false)
	input := &authoringcontract.CapabilityAuthoringSchema{Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed, Required: []string{"id", "name"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"id": {Type: "string", MinLength: identityIntPointer(1)}, "name": {Type: "string", MinLength: identityIntPointer(1)}, "parent_id": {Type: "string"}, "sort_order": {Type: "integer"}, "status": {Type: "string", Enum: []any{"active", "disabled"}, Default: "active"},
	}}
	output := &authoringcontract.CapabilityAuthoringSchema{Schema: input.Schema, Type: "object", AdditionalProperties: closed, Required: []string{"id", "name", "path", "ancestor_ids", "depth", "sort_order", "status"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"id": {Type: "string"}, "name": {Type: "string"}, "parent_id": {Type: "string"}, "path": {Type: "string"}, "ancestor_ids": {Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Type: "string"}}, "depth": {Type: "integer"}, "sort_order": {Type: "integer"}, "status": {Type: "string", Enum: []any{"active", "disabled"}},
	}}
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.department", Status: "supported", Lifecycle: "immediate_audited_configuration",
		Parameters:  []authoringcontract.CapabilityAuthoringParameter{{Key: "id", Type: "string", Required: true}, {Key: "name", Type: "string", Required: true}, {Key: "parent_id", Type: "string"}, {Key: "sort_order", Type: "integer"}, {Key: "status", Type: "string", Default: "active", Enum: []string{"active", "disabled"}}},
		AuditEvents: []string{"identity_department_created", "identity_department_updated"}, ValidationEndpoint: "POST /identity/departments/{departmentID}/validate",
		ConfigurationRoutes: []string{"POST /identity/departments", "PATCH /identity/departments/{departmentID}", "GET /identity/departments/{departmentID}", "GET /identity/departments/{departmentID}/versions"}, ResourceKeyPathParameter: "departmentID", InputSchema: input, OutputSchema: output,
		ResourceOperations: identityAuditedResourceOperations("POST /identity/departments/{departmentID}/validate", "PATCH /identity/departments/{departmentID}", "GET /identity/departments/{departmentID}", "GET /identity/departments/{departmentID}/versions", ""),
		OutputVariables:    []authoringcontract.CapabilityAuthoringOutput{{Name: "department_id", JSONPointer: "/id", Type: "department_id", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{{Kind: "department_id", InputJSONPointer: "/parent_id", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/department_id"}},
		Execution:          identityManagementExecution([]string{"identity.department"}, "identity.department", "stable_department_id_upsert", "identity_department_updated"),
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.identity.department_id_required", FieldPath: "id", MessageKey: "backend.identity.department_id_required"}, {Code: "backend.identity.department_name_required", FieldPath: "name", MessageKey: "backend.identity.department_name_required"},
			{Code: "backend.identity.department_name_exists", FieldPath: "name", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.department_name_exists"}, {Code: "backend.identity.parent_department_not_found", FieldPath: "parent_id", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.parent_department_not_found"},
			{Code: "backend.identity.department_parent_self", FieldPath: "parent_id", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.department_parent_self"}, {Code: "backend.identity.department_cycle", FieldPath: "parent_id", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.department_cycle"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"id": "sales", "name": "Sales", "status": "active"}},
			{Name: "representative", Value: map[string]any{"id": "sales", "name": "Sales", "parent_id": "company", "sort_order": 10, "status": "active"}},
			{Name: "invalid_with_repair", Value: map[string]any{"id": "sales", "name": "Sales", "parent_id": "sales", "status": "active"}, ExpectedErrorCodes: []string{"backend.identity.department_parent_self"}},
		}, Sources: identityManagementAuthoringSources("IdentityDepartment", "ValidateDepartmentConfiguration"),
	}
}

func IdentityUserRoleAssignmentAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed := identityBoolPointer(false)
	input := &authoringcontract.CapabilityAuthoringSchema{Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed, Required: []string{"role_id"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"role_id": {Type: "string", MinLength: identityIntPointer(1)}, "workforce_profile_id": {Type: "string"}, "binding_key": {Type: "string"}, "profile_id": {Type: "string"},
		"valid_from": {Type: "string", Format: "date-time"}, "valid_until": {Type: "string", Format: "date-time"}, "grant_reason": {Type: "string"},
		"expires_at": {Type: "string", Format: "date-time"},
	}}
	output := &authoringcontract.CapabilityAuthoringSchema{Schema: input.Schema, Type: "object", AdditionalProperties: closed, Required: []string{"user_id", "role_id"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"user_id": {Type: "string"}, "role_id": {Type: "string"}, "workforce_profile_id": {Type: "string"}, "binding_key": {Type: "string"}, "profile_id": {Type: "string"},
		"source": {Type: "string"}, "status": {Type: "string"}, "valid_from": {Type: "string", Format: "date-time"}, "valid_until": {Type: "string", Format: "date-time"},
		"granted_by": {Type: "string"}, "grant_reason": {Type: "string"}, "revoked_by": {Type: "string"}, "revoked_at": {Type: "string", Format: "date-time"}, "revoke_reason": {Type: "string"},
		"expires_at": {Type: "string", Format: "date-time"},
	}}
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.user_role_assignment", Status: "supported", Lifecycle: "immediate_audited_configuration", Requires: []string{"identity.user", "identity.role"},
		Parameters: []authoringcontract.CapabilityAuthoringParameter{{Key: "role_id", Type: "string", Required: true}, {Key: "workforce_profile_id", Type: "string"}, {Key: "binding_key", Type: "string"}, {Key: "profile_id", Type: "string"}, {Key: "valid_from", Type: "string", Format: "date-time"}, {Key: "valid_until", Type: "string", Format: "date-time"}, {Key: "grant_reason", Type: "string"}, {Key: "expires_at", Type: "string", Format: "date-time"}}, AuditEvents: []string{"identity_user_role_assigned", "identity_user_role_removed"},
		ValidationEndpoint: "POST /identity/users/{userID}/role-assignments/validate", ConfigurationRoutes: []string{"POST /identity/users/{userID}/role-assignments", "GET /identity/users/{userID}/role-assignments", "GET /identity/users/{userID}/role-assignments/versions", "DELETE /identity/users/{userID}/role-assignments/{roleID}"}, ResourceKeyPathParameter: "userID", InputSchema: input, OutputSchema: output,
		ResourceOperations: identityAuditedResourceOperations("POST /identity/users/{userID}/role-assignments/validate", "POST /identity/users/{userID}/role-assignments", "GET /identity/users/{userID}/role-assignments", "GET /identity/users/{userID}/role-assignments/versions", "DELETE /identity/users/{userID}/role-assignments/{roleID}"),
		OutputVariables:    []authoringcontract.CapabilityAuthoringOutput{{Name: "role_assignments", JSONPointer: "/", Type: "identity_user_role_assignment_list", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{{Kind: "user_id", InputJSONPointer: "/@path/userID", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/user_id"}, {Kind: "role_id", InputJSONPointer: "/role_id", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/role_id"}},
		Execution:          identityManagementExecution([]string{"identity.user", "identity.role"}, "identity.user_role_assignment", "stable_user_role_pair_upsert", "identity_user_role_assigned"),
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.identity.user_not_found", FieldPath: "user_id", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.user_not_found"}, {Code: "backend.identity.role_not_found", FieldPath: "role_id", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.role_not_found"},
			{Code: "backend.identity.assignment_expires_at_invalid", FieldPath: "expires_at", ParameterKeys: []string{"actual", "expected"}, MessageKey: "backend.identity.assignment_expires_at_invalid"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"role_id": "sales_role"}},
			{Name: "representative", Value: map[string]any{"role_id": "sales_role", "expires_at": "2030-01-01T00:00:00Z"}},
			{Name: "invalid_with_repair", Value: map[string]any{"role_id": "sales_role", "expires_at": "tomorrow"}, ExpectedErrorCodes: []string{"backend.identity.assignment_expires_at_invalid"}},
		}, Sources: identityManagementAuthoringSources("IdentityUserRoleAssignment", "ValidateRoleAssignmentConfiguration"),
	}
}

func identityUserOutputSchema(closed *bool) *authoringcontract.CapabilityAuthoringSchema {
	return &authoringcontract.CapabilityAuthoringSchema{Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed, Required: []string{"id", "name", "email", "account_type", "status", "version", "created_at", "updated_at"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"id": {Type: "string"}, "name": {Type: "string"},
		"given_name": {Type: "string"}, "middle_name": {Type: "string"}, "family_name": {Type: "string"},
		"name_prefix": {Type: "string"}, "name_suffix": {Type: "string"}, "native_name": {Type: "string"}, "name_locale": {Type: "string"},
		"email": {Type: "string", Format: "email"}, "phone": {Type: "string"},
		"account_type": {Type: "string", Enum: []any{"human", "service", "automation"}}, "locale": {Type: "string"}, "timezone": {Type: "string"},
		"status": {Type: "string", Enum: []any{"active", "disabled"}}, "version": {Type: "integer"}, "created_at": {Type: "string", Format: "date-time"}, "updated_at": {Type: "string", Format: "date-time"},
	}}
}

func identityManagementExecution(readSet []string, writeSet, idempotency, event string) *authoringcontract.CapabilityAuthoringExecution {
	return &authoringcontract.CapabilityAuthoringExecution{ReadSet: readSet, WriteSet: []string{writeSet}, Transaction: "identity_repository_transaction", Idempotency: idempotency, SideEffects: []string{"audit:" + event}, SideEffectLevel: "internal", PermissionModel: authoringcontract.CapabilityPermissionModelExactAction, ChangeControl: "direct_audited_configuration"}
}

func identityManagementAuthoringSources(modelSymbol, validationSymbol string) []authoringcontract.CapabilityAuthoringSource {
	return []authoringcontract.CapabilityAuthoringSource{
		{Kind: "contract", Path: "internal/domain/identity/contract/identity_management_authoring.go"},
		{Kind: "model", Path: "internal/domain/identity/model/identity_model.go", Symbol: modelSymbol},
		{Kind: "validation", Path: "internal/domain/identity/service/identity_configuration_domain_service.go", Symbol: validationSymbol},
		{Kind: "http", Path: "internal/transport/http/identity/identity_routes.go", Symbol: "RegisterRoutes"},
	}
}
