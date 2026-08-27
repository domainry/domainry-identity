package contract

import (
	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func IdentityRoleDataScopeAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed := identityBoolPointer(false)
	definitions := identityPolicySchemaDefinitions()
	scope := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Required: []string{"resource", "scope"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"resource": {Type: "string", MinLength: identityIntPointer(1)}, "scope": {Type: "string", Enum: identityStringsToAny(identitymodel.AuthoringDataScopeValues())},
		"audit_denial": {Type: "boolean", Default: false}, "predicate": {Ref: "#/$defs/identity_policy_expression"},
	}}
	input := &authoringcontract.CapabilityAuthoringSchema{Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed, Required: []string{"data_scopes"}, Definitions: definitions, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"data_scopes": {Type: "array", Items: &scope},
	}}
	output := &authoringcontract.CapabilityAuthoringSchema{Schema: input.Schema, Type: "array", Items: &scope, Definitions: definitions}
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.role_data_scope", Status: "supported", Lifecycle: "versioned_metadata", Requires: []string{"identity.role", "schema.object"},
		SystemDraftResourceType: "role",
		Parameters:              []authoringcontract.CapabilityAuthoringParameter{{Key: "data_scopes", Type: "array", Required: true, ItemSchema: "identity_data_scope_policy"}},
		Permissions:             []string{"identity.data_scopes.write"}, AuditEvents: []string{"identity_change_plan.item_applied"}, ValidationEndpoint: "POST /identity/roles/{roleID}/data-scopes/validate",
		ConfigurationRoutes: identityReviewedSystemDraftRoutes("POST /identity/roles/{roleID}/data-scopes/validate", "GET /identity/roles/{roleID}/data-scopes"), ResourceKeyPathParameter: "roleID",
		InputSchema: input, OutputSchema: output,
		OutputVariables:    []authoringcontract.CapabilityAuthoringOutput{{Name: "data_scopes", JSONPointer: "/", Type: "identity_data_scope_list", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{{Kind: "role_id", InputJSONPointer: "/@path/roleID", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/role_id"}, {Kind: "object_key", InputJSONPointer: "/data_scopes/*/resource", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/object_key"}},
		Execution:          identityPolicyExecution("identity.role_data_scope", "replace_data_scope_set", "identity_role_data_scopes_updated", "identity.data_scopes.write"),
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.change_plan.system_draft_required", FieldPath: "data_scopes", MessageKey: "backend.change_plan.system_draft_required"},
			{Code: "backend.identity.data_scope_invalid", FieldPath: "data_scopes[].scope", ParameterKeys: []string{"allowed", "actual"}, MessageKey: "backend.identity.data_scope_invalid"},
			{Code: "backend.identity.data_scope_resource_required", FieldPath: "data_scopes[].resource", MessageKey: "backend.identity.data_scope_resource_required"},
			{Code: "backend.identity.data_scope_resource_duplicate", FieldPath: "data_scopes[].resource", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.data_scope_resource_duplicate"},
			{Code: "backend.identity.data_scope_resource_not_found", FieldPath: "data_scopes[].resource", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.data_scope_resource_not_found"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"data_scopes": []any{map[string]any{"resource": "order", "scope": "all_records"}}}},
			{Name: "representative", Value: map[string]any{"data_scopes": []any{map[string]any{"resource": "order", "scope": "custom", "audit_denial": true, "predicate": map[string]any{"operator": "eq", "field_key": "owner", "value_source": "actor_claim", "claim_key": "user_id"}}}}},
			{Name: "invalid_with_repair", Value: map[string]any{"data_scopes": []any{map[string]any{"resource": "order", "scope": "all"}}}, ExpectedErrorCodes: []string{"backend.identity.data_scope_invalid"}},
		}, Sources: identityPolicyAuthoringSources("IdentityDataScopePolicy", "ValidateRoleDataScopes"),
	}
}

func IdentityRoleFieldPermissionAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed := identityBoolPointer(false)
	definitions := identityPolicySchemaDefinitions()
	mask := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Required: []string{"type"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{"type": {Type: "string", Enum: []any{"phone", "id_number", "email", "year_only", "last_n"}}, "last_n": {Type: "integer", Minimum: identityFloatPointer(1), Maximum: identityFloatPointer(32)}}}
	rule := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Required: []string{"key", "priority", "actions", "effect"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"key": {Type: "string", MinLength: identityIntPointer(1)}, "priority": {Type: "integer"}, "actions": {Type: "array", MinItems: identityIntPointer(1), Items: &authoringcontract.CapabilityAuthoringSchema{Type: "string", Enum: []any{"read", "write", "export", "report", "audit"}}},
		"effect": {Type: "string", Enum: []any{"allow", "deny", "hide", "mask"}}, "predicate": {Ref: "#/$defs/identity_policy_expression"}, "mask_strategy": mask, "audit_denial": {Type: "boolean", Default: false},
	}}
	permission := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Required: []string{"resource", "field", "visible", "editable"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"resource": {Type: "string", MinLength: identityIntPointer(1)}, "field": {Type: "string", MinLength: identityIntPointer(1)}, "visible": {Type: "boolean"}, "editable": {Type: "boolean"}, "masked": {Type: "boolean", Default: false}, "policies": {Type: "array", Items: &rule},
	}}
	input := &authoringcontract.CapabilityAuthoringSchema{Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed, Required: []string{"field_permissions"}, Definitions: definitions, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{"field_permissions": {Type: "array", Items: &permission}}}
	output := &authoringcontract.CapabilityAuthoringSchema{Schema: input.Schema, Type: "array", Items: &permission, Definitions: definitions}
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.role_field_permission", Status: "supported", Lifecycle: "versioned_metadata", Requires: []string{"identity.role", "schema.field"},
		SystemDraftResourceType: "role",
		Parameters:              []authoringcontract.CapabilityAuthoringParameter{{Key: "field_permissions", Type: "array", Required: true, ItemSchema: "identity_field_permission"}}, Permissions: []string{"identity.field_permissions.write"}, AuditEvents: []string{"identity_change_plan.item_applied"},
		ValidationEndpoint: "POST /identity/roles/{roleID}/field-permissions/validate", ConfigurationRoutes: identityReviewedSystemDraftRoutes("POST /identity/roles/{roleID}/field-permissions/validate", "GET /identity/roles/{roleID}/field-permissions"), ResourceKeyPathParameter: "roleID",
		InputSchema: input, OutputSchema: output,
		OutputVariables:    []authoringcontract.CapabilityAuthoringOutput{{Name: "field_permissions", JSONPointer: "/", Type: "identity_field_permission_list", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{{Kind: "role_id", InputJSONPointer: "/@path/roleID", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/role_id"}, {Kind: "object_key", InputJSONPointer: "/field_permissions/*/resource", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/object_key"}, {Kind: "field_key", InputJSONPointer: "/field_permissions/*/field", ScopeFrom: "/field_permissions/*/resource", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/field_key?scope={object_key}"}},
		Execution:          identityPolicyExecution("identity.role_field_permission", "replace_field_permission_set", "identity_role_field_permissions_updated", "identity.field_permissions.write"),
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.change_plan.system_draft_required", FieldPath: "field_permissions", MessageKey: "backend.change_plan.system_draft_required"},
			{Code: "backend.identity.field_permission_resource_not_found", FieldPath: "field_permissions[].resource", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.field_permission_resource_not_found"},
			{Code: "backend.identity.field_permission_field_not_found", FieldPath: "field_permissions[].field", ParameterKeys: []string{"resource", "actual"}, MessageKey: "backend.identity.field_permission_field_not_found"},
			{Code: "backend.identity.field_permission_duplicate", FieldPath: "field_permissions[]", ParameterKeys: []string{"resource", "field"}, MessageKey: "backend.identity.field_permission_duplicate"},
			{Code: "backend.identity.field_permission_edit_requires_visibility", FieldPath: "field_permissions[].editable", ParameterKeys: []string{"expected", "actual"}, MessageKey: "backend.identity.field_permission_edit_requires_visibility"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"field_permissions": []any{map[string]any{"resource": "order", "field": "total_amount", "visible": true, "editable": false}}}},
			{Name: "representative", Value: map[string]any{"field_permissions": []any{map[string]any{"resource": "order", "field": "total_amount", "visible": true, "editable": false, "masked": true}}}},
			{Name: "invalid_with_repair", Value: map[string]any{"field_permissions": []any{map[string]any{"resource": "order", "field": "total_amount", "visible": false, "editable": true}}}, ExpectedErrorCodes: []string{"backend.identity.field_permission_edit_requires_visibility"}},
		}, Sources: identityPolicyAuthoringSources("IdentityFieldPermission", "ValidateRoleFieldPermissions"),
	}
}

func IdentityMenuAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed := identityBoolPointer(false)
	input := &authoringcontract.CapabilityAuthoringSchema{Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed, Required: []string{"id", "key", "label", "status"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"id": {Type: "string", MinLength: identityIntPointer(1)}, "key": {Type: "string", MinLength: identityIntPointer(1)}, "label": {Type: "string", MinLength: identityIntPointer(1)}, "description": {Type: "string"}, "route": {Type: "string"}, "icon": {Type: "string"}, "parent_id": {Type: "string"}, "sort_order": {Type: "integer", Minimum: identityFloatPointer(0)}, "audience": {Type: "string"}, "status": {Type: "string", Enum: []any{"active", "disabled"}},
	}}
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.menu", Status: "supported", Lifecycle: "immediate_audited_configuration", Parameters: []authoringcontract.CapabilityAuthoringParameter{{Key: "id", Type: "string", Required: true}, {Key: "key", Type: "string", Required: true}, {Key: "label", Type: "string", Required: true}, {Key: "description", Type: "string"}, {Key: "route", Type: "string"}, {Key: "icon", Type: "string"}, {Key: "parent_id", Type: "string"}, {Key: "sort_order", Type: "integer", Minimum: identityFloatPointer(0)}, {Key: "audience", Type: "string"}, {Key: "status", Type: "string", Required: true, Enum: []string{"active", "disabled"}}},
		Permissions: []string{"identity.menus.write"}, AuditEvents: []string{"identity_menu_upserted", "identity_menu_deleted"}, ValidationEndpoint: "POST /identity/menus/{menuID}/validate", ConfigurationRoutes: []string{"PUT /identity/menus/{menuID}", "GET /identity/menus/{menuID}", "GET /identity/menus/{menuID}/versions", "DELETE /identity/menus/{menuID}"}, ResourceKeyPathParameter: "menuID", InputSchema: input, OutputSchema: input,
		ResourceOperations: identityAuditedResourceOperations("POST /identity/menus/{menuID}/validate", "PUT /identity/menus/{menuID}", "GET /identity/menus/{menuID}", "GET /identity/menus/{menuID}/versions", "DELETE /identity/menus/{menuID}"),
		OutputVariables:    []authoringcontract.CapabilityAuthoringOutput{{Name: "menu_id", JSONPointer: "/id", Type: "menu_id", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{{Kind: "menu_id", InputJSONPointer: "/parent_id", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/menu_id"}},
		Execution:          identityDirectPolicyExecution("identity.menu", "stable_menu_id_upsert", "identity_menu_upserted", "identity.menus.write"),
		Errors:             []authoringcontract.CapabilityAuthoringError{{Code: "backend.identity.menu_parent_not_found", FieldPath: "parent_id", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.menu_parent_not_found"}, {Code: "backend.identity.menu_parent_cycle", FieldPath: "parent_id", MessageKey: "backend.identity.menu_parent_cycle"}},
		Examples:           []authoringcontract.CapabilityAuthoringExample{{Name: "minimal_valid", Value: map[string]any{"id": "orders", "key": "orders", "label": "Orders", "status": "active"}}, {Name: "representative", Value: map[string]any{"id": "orders", "key": "orders", "label": "Orders", "route": "/objects/order", "icon": "shopping-cart", "sort_order": 100, "status": "active"}}, {Name: "invalid_with_repair", Value: map[string]any{"id": "orders", "key": "orders", "label": "Orders", "parent_id": "missing", "status": "active"}, ExpectedErrorCodes: []string{"backend.identity.menu_parent_not_found"}}}, Sources: identityPolicyAuthoringSources("IdentityMenu", "ValidateMenu"),
	}
}

func IdentityRoleMenuAssignmentAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed := identityBoolPointer(false)
	input := &authoringcontract.CapabilityAuthoringSchema{
		Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed, Required: []string{"menu_ids"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"menu_ids": {Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Type: "string", MinLength: identityIntPointer(1)}},
		},
	}
	assignment := authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: closed, Required: []string{"role_id", "menu_id"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"role_id": {Type: "string", MinLength: identityIntPointer(1)},
			"menu_id": {Type: "string", MinLength: identityIntPointer(1)},
		},
	}
	output := &authoringcontract.CapabilityAuthoringSchema{
		Schema: "https://json-schema.org/draft/2020-12/schema", Type: "array", Items: &assignment,
	}
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.role_menu_assignment", Status: "supported", Lifecycle: "immediate_audited_configuration", Requires: []string{"identity.role", "identity.menu"},
		Parameters:  []authoringcontract.CapabilityAuthoringParameter{{Key: "menu_ids", Type: "array", Required: true, ItemSchema: "menu_id"}},
		Permissions: []string{"identity.menus.write"}, AuditEvents: []string{"identity_role_menus_updated"},
		ValidationEndpoint: "POST /identity/roles/{roleID}/menus/validate", ConfigurationRoutes: []string{"PUT /identity/roles/{roleID}/menus", "GET /identity/roles/{roleID}/menus", "GET /identity/roles/{roleID}/menus/versions"},
		ResourceOperations:       identityAuditedResourceOperations("POST /identity/roles/{roleID}/menus/validate", "PUT /identity/roles/{roleID}/menus", "GET /identity/roles/{roleID}/menus", "GET /identity/roles/{roleID}/menus/versions", ""),
		ResourceKeyPathParameter: "roleID", InputSchema: input, OutputSchema: output,
		OutputVariables: []authoringcontract.CapabilityAuthoringOutput{{Name: "menu_assignments", JSONPointer: "/", Type: "identity_role_menu_assignment_list", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{
			{Kind: "role_id", InputJSONPointer: "/@path/roleID", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/role_id"},
			{Kind: "menu_id", InputJSONPointer: "/menu_ids/*", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/menu_id"},
		},
		Execution: &authoringcontract.CapabilityAuthoringExecution{
			ReadSet: []string{"identity.role", "identity.menu"}, WriteSet: []string{"identity.role_menu_assignment"}, Transaction: "identity_repository_transaction", Idempotency: "replace_menu_assignment_set",
			SideEffects: []string{"audit:identity_role_menus_updated"}, SideEffectLevel: "internal", PermissionModel: "identity.menus.write", ChangeControl: "direct_on_configuring_runtime_change_plan_on_existing_runtime",
		},
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.identity.role_not_found", FieldPath: "role_id", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.role_not_found"},
			{Code: "backend.identity.menu_not_found", FieldPath: "menu_ids[]", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.menu_not_found"},
			{Code: "backend.identity.menu_assignment_duplicate", FieldPath: "menu_ids[]", ParameterKeys: []string{"actual"}, MessageKey: "backend.identity.menu_assignment_duplicate"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"menu_ids": []any{"orders"}}},
			{Name: "representative", Value: map[string]any{"menu_ids": []any{"orders", "reports"}}},
			{Name: "invalid_with_repair", Value: map[string]any{"menu_ids": []any{"orders", "orders"}}, ExpectedErrorCodes: []string{"backend.identity.menu_assignment_duplicate"}},
		},
		Sources: identityPolicyAuthoringSources("IdentityRoleMenuAssignment", "ValidateRoleMenus"),
	}
}

func identityPolicySchemaDefinitions() map[string]authoringcontract.CapabilityAuthoringSchema {
	closed := identityBoolPointer(false)
	segment := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Required: []string{"direction", "relation_field_key", "target_object_key"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{"direction": {Type: "string", Enum: []any{"forward", "reverse"}}, "relation_field_key": {Type: "string"}, "target_object_key": {Type: "string"}}}
	expression := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Required: []string{"operator"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"operator": {Type: "string", Enum: []any{"and", "or", "not", "eq", "in"}}, "path": {Type: "array", MaxItems: identityIntPointer(3), Items: &authoringcontract.CapabilityAuthoringSchema{Ref: "#/$defs/identity_policy_relation_segment"}}, "field_key": {Type: "string"}, "value_source": {Type: "string", Enum: []any{"literal", "actor_claim"}}, "claim_key": {Type: "string"}, "values": {Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Type: "string"}}, "children": {Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Ref: "#/$defs/identity_policy_expression"}},
	}}
	return map[string]authoringcontract.CapabilityAuthoringSchema{"identity_policy_relation_segment": segment, "identity_policy_expression": expression}
}

func identityPolicyExecution(writeSet, idempotency, event, permission string) *authoringcontract.CapabilityAuthoringExecution {
	return &authoringcontract.CapabilityAuthoringExecution{ReadSet: []string{"identity.role", "metadata.schema"}, WriteSet: []string{writeSet}, Transaction: "reviewed_change_plan_transaction", Idempotency: idempotency, SideEffects: []string{"audit:" + event, "schema_snapshot_rebuild"}, SideEffectLevel: "internal", Compensation: "restore_as_new_system_draft", PermissionModel: permission, ChangeControl: "reviewed_system_draft_change_plan"}
}

func identityDirectPolicyExecution(writeSet, idempotency, event, permission string) *authoringcontract.CapabilityAuthoringExecution {
	return &authoringcontract.CapabilityAuthoringExecution{ReadSet: []string{writeSet}, WriteSet: []string{writeSet}, Transaction: "identity_repository_transaction", Idempotency: idempotency, SideEffects: []string{"audit:" + event}, SideEffectLevel: "internal", PermissionModel: permission, ChangeControl: "immediate_audited_configuration"}
}

func identityPolicyAuthoringSources(modelSymbol, validationSymbol string) []authoringcontract.CapabilityAuthoringSource {
	return []authoringcontract.CapabilityAuthoringSource{{Kind: "contract", Path: "internal/domain/identity/contract/identity_policy_authoring.go"}, {Kind: "model", Path: "internal/domain/identity/model/identity_model.go", Symbol: modelSymbol}, {Kind: "validation", Path: "internal/application/identity/identity_governance_application_service.go", Symbol: validationSymbol}, {Kind: "http", Path: "internal/transport/http/identity/identity_routes.go", Symbol: "RegisterRoutes"}}
}

func identityStringsToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func identityFloatPointer(value float64) *float64 { return &value }
