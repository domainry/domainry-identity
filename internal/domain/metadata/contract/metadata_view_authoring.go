package contract

import authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"

func MetadataViewAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	payload := metadataViewPayloadSchema()
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "view.definition", Status: "supported", Lifecycle: "versioned_metadata", Requires: []string{"schema.object"},
		SystemDraftResourceType: "view",
		Parameters:              []authoringcontract.CapabilityAuthoringParameter{{Key: "key", Type: "string", Required: true, MinLength: metadataIntPointer(1)}, {Key: "name", Type: "string", Required: true, MinLength: metadataIntPointer(1)}, {Key: "object_key", Type: "object_key", Required: true}, {Key: "type", Type: "string", Required: true}, metadataExpectedSchemaHashParameter()},
		Permissions:             []string{"workspace.admin"}, AuditEvents: []string{"view_registry_saved"},
		ValidationEndpoint: "POST /metadata/definitions/view/{resourceKey}/validate", ConfigurationRoutes: metadataConfigurationRoutes("view"), ResourceKeyPathParameter: "resourceKey",
		ResourceOperations: metadataResourceOperations("view"),
		InputSchema:        metadataAuthoringRequestSchema(payload, false), OutputSchema: metadataAuthoringOutputSchema(payload),
		OutputVariables:    []authoringcontract.CapabilityAuthoringOutput{{Name: "resource_key", JSONPointer: "/definition/resource_key", Type: "view_key", VisibleTo: "subsequent_capability_calls"}, {Name: "schema_hash", JSONPointer: "/definition/schema_hash", Type: "schema_hash", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{metadataObjectReference("/payload/object_key")}, Execution: metadataAuthoringExecution("view.definition"),
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.metadata.view_definition_invalid", FieldPath: "payload", MessageKey: "backend.metadata.view_definition_invalid"}, {Code: "backend.metadata.view_key_mismatch", FieldPath: "payload.key", MessageKey: "backend.metadata.view_key_mismatch"},
			{Code: "backend.metadata.view_name_required", FieldPath: "payload.name", MessageKey: "backend.metadata.view_name_required"}, {Code: "backend.metadata.view_object_required", FieldPath: "payload.object_key", MessageKey: "backend.metadata.view_object_required"},
			{Code: "backend.metadata.view_object_not_found", FieldPath: "payload.object_key", MessageKey: "backend.metadata.view_object_not_found"}, {Code: "backend.metadata.view_type_required", FieldPath: "payload.type", MessageKey: "backend.metadata.view_type_required"},
			{Code: "backend.metadata.view_config_unknown", FieldPath: "payload.config", MessageKey: "backend.metadata.view_config_unknown"}, {Code: "backend.metadata.view_config_invalid", FieldPath: "payload.config", MessageKey: "backend.metadata.view_config_invalid"},
			{Code: "backend.metadata.view_page_size_invalid", FieldPath: "payload.config.page_size", MessageKey: "backend.metadata.view_page_size_invalid"}, {Code: "backend.metadata.view_field_not_found", FieldPath: "payload.config", MessageKey: "backend.metadata.view_field_not_found"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"expected_schema_hash": "$instance.schema_hash", "payload": map[string]any{"key": "order_list", "name": "Orders", "object_key": "order", "type": "table", "config": map[string]any{}}}},
			{Name: "representative", Value: map[string]any{"expected_schema_hash": "$instance.schema_hash", "name": "Orders", "source_kind": "builder_v4", "source_id": "$builder_task_id", "payload": map[string]any{"key": "order_list", "name": "Orders", "object_key": "order", "type": "table", "config": map[string]any{"business_view": "list", "columns": []any{"number", "status"}, "search_fields": []any{"number"}, "sort": []any{"-created_at"}, "page_size": 50}}}},
			{Name: "invalid_with_repair", Value: map[string]any{"expected_schema_hash": "$instance.schema_hash", "payload": map[string]any{"key": "order_list", "name": "Orders", "object_key": "missing", "type": "table", "config": map[string]any{}}}, ExpectedErrorCodes: []string{"backend.metadata.view_object_not_found"}},
		},
		Sources: []authoringcontract.CapabilityAuthoringSource{{Kind: "contract", Path: "internal/domain/metadata/contract/metadata_view_authoring.go", Symbol: "MetadataViewAuthoringCapability"}, {Kind: "validation", Path: "internal/domain/metadata/validation/metadata_view_validation.go", Symbol: "MetadataValidateViewDefinition"}, {Kind: "service", Path: "internal/application/metadata/metadata_definition_orchestration_application_service.go", Symbol: "MetadataApplicationService.UpsertMetadataDefinition"}},
	}
}
