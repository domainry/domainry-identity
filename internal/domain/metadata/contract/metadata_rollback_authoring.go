package contract

import authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"

func MetadataRollbackAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "maintenance.metadata_rollback", Status: "supported", Lifecycle: "restore_version_as_new_system_draft", Requires: []string{"maintenance.reference_impact"},
		SystemDraftResourceTypeInputJSONPointer: "/resource_type",
		Parameters:                              []authoringcontract.CapabilityAuthoringParameter{{Key: "resource_type", Type: "string", Required: true}, {Key: "resource_key", Type: "string", Required: true}, {Key: "target_version", Type: "string", Required: true}, {Key: "expected_schema_hash", Type: "string", Required: true}, {Key: "expected_reference_graph_hash", Type: "string", Required: true}, {Key: "business_reason", Type: "string", Required: true}, {Key: "change_plan_id", Type: "string", Required: true}, {Key: "authoring_contract_version", Type: "string", Required: true}, {Key: "authoring_contract_hash", Type: "string", Required: true}},
		Permissions:                             []string{"workspace.admin"}, ValidationEndpoint: "POST /tenant-admin/change-plans/validate", ConfigurationRoutes: []string{"GET /metadata/definitions/{resourceType}/{resourceKey}/versions", "GET /domain-system-snapshot", "GET /domain-reference-graph", "GET /tenant-admin/change-plans/{planID}", "PUT /tenant-admin/change-plans/{planID}", "POST /tenant-admin/change-plans/{planID}/simulate", "POST /tenant-admin/change-plans/{planID}/review", "POST /tenant-admin/change-plans/{planID}/approve", "POST /tenant-admin/change-plans/apply"}, AuditEvents: []string{"identity_change_plan.item_applied"},
		InputSchema:  metadataRollbackInputSchema(),
		OutputSchema: metadataRollbackOutputSchema(), OutputVariables: []authoringcontract.CapabilityAuthoringOutput{{Name: "schema_hash", JSONPointer: "/definition/schema_hash", Type: "schema_hash", VisibleTo: "subsequent_capability_calls"}, {Name: "snapshot_hash", JSONPointer: "/schema/snapshot_hash", Type: "snapshot_hash", VisibleTo: "subsequent_capability_calls"}},
		Execution: &authoringcontract.CapabilityAuthoringExecution{ReadSet: []string{"metadata.definition_version", "changeplan.reference_graph"}, WriteSet: []string{"metadata.definition_version", "metadata.schema_snapshot", "changeplan.operation_receipt"}, Transaction: "reviewed_change_plan_transaction", Idempotency: "idempotency_key_and_plan_revision", SideEffects: []string{"audit:identity_change_plan.item_applied", "schema_snapshot_rebuild"}, SideEffectLevel: "internal", Compensation: "restore_as_new_system_draft", PermissionModel: "workspace.admin", ChangeControl: "reviewed_system_draft_change_plan"},
		Examples:  metadataRollbackExamples(),
		Errors:    []authoringcontract.CapabilityAuthoringError{{Code: "backend.metadata.rollback_contract_required", FieldPath: "rollback", MessageKey: "backend.metadata.rollback_contract_required"}, {Code: "backend.metadata.rollback_contract_stale", FieldPath: "authoring_contract_hash", MessageKey: "backend.metadata.rollback_contract_stale"}, {Code: "backend.metadata.rollback_reference_graph_stale", FieldPath: "expected_reference_graph_hash", MessageKey: "backend.metadata.rollback_reference_graph_stale"}, {Code: "backend.metadata.rollback_target_not_found", FieldPath: "target_version", MessageKey: "backend.metadata.rollback_target_not_found"}},
		Sources:   []authoringcontract.CapabilityAuthoringSource{{Kind: "service", Path: "internal/application/changeplan/changeplan_identity_change_plan_draft_lifecycle_clone.go", Symbol: "CloneCurrentDraft"}, {Kind: "storage", Path: "internal/infrastructure/persistence/database/metadata/definition_context_store.go", Symbol: "ApplyDefinitionMutations"}},
	}
}

func metadataRollbackOutputSchema() *authoringcontract.CapabilityAuthoringSchema {
	closed, open := false, true
	return &authoringcontract.CapabilityAuthoringSchema{Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: &closed, Required: []string{"definition", "schema", "impact"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{"definition": {Type: "object", AdditionalProperties: &open}, "schema": {Type: "object", AdditionalProperties: &open}, "impact": {Type: "object", AdditionalProperties: &open}}}
}

func metadataRollbackExamples() []authoringcontract.CapabilityAuthoringExample {
	minimal := map[string]any{"resource_type": "field", "resource_key": "order.status", "target_version": "v1", "expected_schema_hash": "$instance.schema_hash", "expected_reference_graph_hash": "$instance.reference_graph_hash", "business_reason": "Restore compatible field definition", "change_plan_id": "$change_plan.id", "authoring_contract_version": "$contract.version", "authoring_contract_hash": "$contract.hash"}
	representative := map[string]any{"resource_type": "action", "resource_key": "order.approve", "target_version": "v2", "expected_schema_hash": "$instance.schema_hash", "expected_reference_graph_hash": "$instance.reference_graph_hash", "business_reason": "Rollback failing approval action", "change_plan_id": "$change_plan.id", "change_plan_revision": 3, "builder_task_id": "$builder_task_id", "authoring_contract_version": "$contract.version", "authoring_contract_hash": "$contract.hash"}
	invalid := map[string]any{"resource_type": "field", "resource_key": "order.status", "target_version": "", "expected_schema_hash": "$instance.schema_hash", "expected_reference_graph_hash": "$instance.reference_graph_hash", "business_reason": "Restore field", "change_plan_id": "$change_plan.id", "authoring_contract_version": "$contract.version", "authoring_contract_hash": "$contract.hash"}
	return []authoringcontract.CapabilityAuthoringExample{{Name: "minimal_valid", Value: minimal}, {Name: "representative", Value: representative}, {Name: "invalid_with_repair", Value: invalid, ExpectedErrorCodes: []string{"backend.metadata.rollback_contract_required"}}}
}

func metadataRollbackInputSchema() *authoringcontract.CapabilityAuthoringSchema {
	closed := false
	return &authoringcontract.CapabilityAuthoringSchema{Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: &closed, Required: []string{"resource_type", "resource_key", "target_version", "expected_schema_hash", "expected_reference_graph_hash", "business_reason", "change_plan_id", "authoring_contract_version", "authoring_contract_hash"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"resource_type": {Type: "string"}, "resource_key": {Type: "string"}, "target_version": {Type: "string"}, "expected_schema_hash": {Type: "string"}, "expected_reference_graph_hash": {Type: "string"}, "business_reason": {Type: "string"}, "change_plan_id": {Type: "string"}, "change_plan_revision": {Type: "integer"}, "builder_task_id": {Type: "string"}, "authoring_contract_version": {Type: "string"}, "authoring_contract_hash": {Type: "string"},
	}}
}
