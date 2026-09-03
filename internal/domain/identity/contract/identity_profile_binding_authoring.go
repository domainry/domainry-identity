package contract

import (
	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
)

func IdentityProfileBindingAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed, open := identityBoolPointer(false), identityBoolPointer(true)
	strings := authoringcontract.CapabilityAuthoringSchema{Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Type: "string", MinLength: identityIntPointer(1)}}
	claim := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Required: []string{"claim_key", "field_key"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"claim_key": {Type: "string", MinLength: identityIntPointer(1)}, "field_key": {Type: "string", MinLength: identityIntPointer(1)},
	}}
	claimProof := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Required: []string{"type", "field_key"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"type": {Type: "string", Enum: []any{"email", "phone", "external_idp_subject"}}, "field_key": {Type: "string", MinLength: identityIntPointer(1)},
	}}
	bindingLifecycle := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"allow_unbound": {Type: "boolean"}, "invitation_channels": {Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Type: "string", Enum: []any{"email", "sms", "external_idp"}}},
		"claim_proofs": {Type: "array", Items: &claimProof}, "rebind_requires_approval": {Type: "boolean"}, "rebind_revokes_sessions": {Type: "boolean"},
	}}
	directory := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"enabled": {Type: "boolean"}, "label": {Type: "string"}, "plural_label": {Type: "string"},
		"summary_fields": strings, "filter_fields": strings, "status_field": {Type: "string"}, "action_keys": strings,
	}}
	businessIdentity := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed, Required: []string{"key", "surface_keys"}, Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
		"key": {Type: "string", MinLength: identityIntPointer(1)}, "surface_keys": strings, "status_field": {Type: "string"}, "active_status_values": strings,
		"blacklist_field": {Type: "string"}, "claims": {Type: "array", Items: &claim},
	}}
	payload := authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: closed,
		Required: []string{"object_key", "identity_relation_field", "business_identity", "default_visibility"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"object_key": {Type: "string", MinLength: identityIntPointer(1)}, "identity_relation_field": {Type: "string", MinLength: identityIntPointer(1)},
			"business_identity": businessIdentity,
			"binding_lifecycle": bindingLifecycle,
			"directory":         directory,
			"summary_fields":    strings, "profile_tabs": strings, "profile_tab_labels": {Type: "object", AdditionalProperties: open},
			"profile_tab_fields": {Type: "object", AdditionalProperties: open}, "profile_tab_related_objects": {Type: "object", AdditionalProperties: open},
			"profile_tab_components": {Type: "object", AdditionalProperties: open}, "default_visibility": {Type: "string", Enum: []any{"when_readable", "hidden"}},
			"required_permissions": strings, "standalone_workspace": {Type: "boolean"}, "provenance": {Type: "object", AdditionalProperties: open},
		},
	}
	execution := metadatacontract.VersionedMetadataDefinitionExecution("identity.profile_binding")
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.profile_binding", Status: "supported", Lifecycle: "versioned_metadata", Requires: []string{"schema.object", "schema.relation"},
		Parameters:         []authoringcontract.CapabilityAuthoringParameter{{Key: "object_key", Type: "object_key", Required: true}, {Key: "identity_relation_field", Type: "field_key", Required: true}, {Key: "business_identity", Type: "object", Required: true}, {Key: "expected_schema_hash", Type: "schema_hash", Required: true}},
		AuditEvents:        []string{"metadata_definition_upserted"},
		ValidationEndpoint: "POST /tenant-admin/metadata/definitions/identity_profile_binding/{resourceKey}/validate", ConfigurationRoutes: metadatacontract.VersionedMetadataDefinitionRoutes("identity_profile_binding"), ResourceKeyPathParameter: "resourceKey",
		ResourceOperations: metadatacontract.VersionedMetadataDefinitionOperations("identity_profile_binding"),
		InputSchema:        metadatacontract.VersionedMetadataDefinitionRequestSchema(payload, false), OutputSchema: metadatacontract.VersionedMetadataDefinitionOutputSchema(payload),
		OutputVariables:    []authoringcontract.CapabilityAuthoringOutput{{Name: "resource_key", JSONPointer: "/definition/resource_key", Type: "identity_profile_binding_key", VisibleTo: "subsequent_capability_calls"}, {Name: "schema_hash", JSONPointer: "/definition/schema_hash", Type: "schema_hash", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{{Kind: "object_key", InputJSONPointer: "/payload/object_key", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/object_key"}, {Kind: "field_key", InputJSONPointer: "/payload/identity_relation_field", ScopeFrom: "/payload/object_key", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/field_key"}},
		Execution:          execution,
		Errors:             []authoringcontract.CapabilityAuthoringError{{Code: "backend.identity.profile_binding_invalid", FieldPath: "payload", ParameterKeys: []string{"diagnostic"}, MessageKey: "backend.identity.profile_binding_invalid"}},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"expected_schema_hash": "$instance.schema_hash", "payload": map[string]any{"object_key": "staff_profile", "identity_relation_field": "identity_user", "business_identity": map[string]any{"key": "staff", "surface_keys": []any{"admin"}}, "default_visibility": "when_readable"}}},
			{Name: "representative", Value: map[string]any{"expected_schema_hash": "$instance.schema_hash", "payload": map[string]any{"object_key": "staff_profile", "identity_relation_field": "identity_user", "business_identity": map[string]any{"key": "staff", "surface_keys": []any{"admin"}, "status_field": "status", "active_status_values": []any{"active"}, "claims": []any{map[string]any{"claim_key": "territory_id", "field_key": "territory_id"}}}, "summary_fields": []any{"display_name"}, "default_visibility": "when_readable"}}},
			{Name: "invalid_with_repair", Value: map[string]any{"expected_schema_hash": "$instance.schema_hash", "payload": map[string]any{"object_key": "missing"}}, ExpectedErrorCodes: []string{"backend.identity.profile_binding_invalid"}},
		},
		Sources: []authoringcontract.CapabilityAuthoringSource{{Kind: "contract", Path: "internal/domain/identity/contract/identity_profile_binding_authoring.go", Symbol: "IdentityProfileBindingAuthoringCapability"}, {Kind: "model", Path: "internal/domain/identity/model/identity_profile_extension.go", Symbol: "IdentityProfileExtension"}, {Kind: "validation", Path: "internal/domain/manifest/validation/manifest_validator.go", Symbol: "ValidateIdentityProfileBindings"}, {Kind: "service", Path: "internal/application/metadata/metadata_definition_orchestration_application_service.go", Symbol: "MetadataApplicationService.UpsertMetadataDefinition"}},
	}
}
