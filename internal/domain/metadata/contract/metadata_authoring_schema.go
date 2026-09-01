package contract

import authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"

import "strings"

const (
	metadataJSONSchemaDraft = "https://json-schema.org/draft/2020-12/schema"

	MetadataActionManifestGet          = "identity.metadata.manifest.get"
	MetadataActionReload               = "identity.metadata.reload"
	MetadataActionMigrationPlanGet     = "identity.metadata.migration_plan.get"
	MetadataActionObjectRecordCountGet = "identity.metadata.object_record_count.get"
	MetadataActionDefinitionGet        = "identity.metadata.definition.get"
	MetadataActionDefinitionVersions   = "identity.metadata.definition.versions"
	MetadataActionDefinitionValidate   = "identity.metadata.definition.validate"
	MetadataActionDefinitionUpsert     = "identity.metadata.definition.upsert"
	MetadataActionDefinitionDisable    = "identity.metadata.definition.disable"
	MetadataActionDefinitionRollback   = "identity.metadata.definition.rollback"
)

func metadataAuthoringRequestSchema(payload authoringcontract.CapabilityAuthoringSchema, objectKeyRequired bool) *authoringcontract.CapabilityAuthoringSchema {
	required := []string{"expected_schema_hash", "payload"}
	if objectKeyRequired {
		required = append(required, "object_key")
	}
	return &authoringcontract.CapabilityAuthoringSchema{
		Schema: metadataJSONSchemaDraft, Type: "object", AdditionalProperties: metadataBoolPointer(false), Required: required,
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"object_key":           metadataStringSchema("Runtime object owning this resource."),
			"name":                 metadataStringSchema("Optional display name stored with the definition."),
			"source_kind":          metadataStringSchema("Stable authoring source kind."),
			"source_id":            metadataStringSchema("Stable authoring source identifier."),
			"expected_schema_hash": metadataStringSchema("Current Runtime schema hash used for optimistic concurrency."),
			"payload":              payload,
		},
	}
}

func metadataAuthoringOutputSchema(payload authoringcontract.CapabilityAuthoringSchema) *authoringcontract.CapabilityAuthoringSchema {
	definition := authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: metadataBoolPointer(false),
		Required: []string{"payload", "resource_key", "resource_type", "schema_hash"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"resource_type": {Type: "string"}, "resource_key": {Type: "string"}, "object_key": {Type: "string"}, "name": {Type: "string"},
			"payload": payload, "schema_version": {Type: "string"}, "schema_hash": {Type: "string"}, "source_kind": {Type: "string"}, "source_id": {Type: "string"},
			"disabled_at": {Type: "string"}, "created_at": {Type: "string", Format: "date-time"}, "updated_at": {Type: "string", Format: "date-time"},
		},
	}
	return &authoringcontract.CapabilityAuthoringSchema{
		Schema: metadataJSONSchemaDraft, Type: "object", AdditionalProperties: metadataBoolPointer(false),
		Required: []string{"definition", "resource", "resource_hash", "schema", "snapshot_hash", "available_successors"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"definition": definition, "resource": definition,
			"resource_hash":        {Type: "string"},
			"snapshot_hash":        {Type: "string"},
			"available_successors": {Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{}},
			// The endpoint currently returns the complete Runtime schema snapshot.
			// It remains explicitly open until P3 introduces the bounded V4 result envelope.
			"schema": {Type: "object", AdditionalProperties: metadataBoolPointer(true)},
		},
	}
}

func metadataObjectPayloadSchema() authoringcontract.CapabilityAuthoringSchema {
	capabilities := authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: metadataBoolPointer(false),
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"create": {Type: "boolean", Default: true}, "read": {Type: "boolean", Default: true},
			"update": {Type: "boolean", Default: true}, "delete": {Type: "boolean", Default: true},
			"export": {Type: "boolean", Default: true},
		},
	}
	lifecyclePolicy := authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: metadataBoolPointer(false), Required: []string{"mode"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"mode":             {Type: "string", Enum: []any{"mutable", "soft_delete_only", "append_only", "immutable_after_state"}},
			"state_field":      {Type: "string"},
			"immutable_states": {Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Type: "string"}},
		},
	}
	ledgerPolicy := authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: metadataBoolPointer(false), Required: []string{"integrity"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"integrity": {Type: "string", Enum: []any{"sha256_chain"}},
			"signature": {Type: "string", Enum: []any{"none", "hmac_sha256"}, Default: "none"},
		},
	}
	exportAssurancePolicy := authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: metadataBoolPointer(false), Required: []string{"required_methods"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"required_methods":              {Type: "array", MinItems: metadataIntPointer(1), Items: &authoringcontract.CapabilityAuthoringSchema{Type: "string", Enum: []any{"normal_login", "recent_reauth", "otp", "maker_checker", "workflow_approval"}}},
			"recent_reauth_max_age_seconds": {Type: "integer", Minimum: metadataFloatPointer(1), Maximum: metadataFloatPointer(86400)},
		},
	}
	ux := authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: metadataBoolPointer(false),
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"kind": {Type: "string", Enum: []any{"identity_profile_extension"}},
			"config": {Type: "object", AdditionalProperties: metadataBoolPointer(false), Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
				"identity_relation_field": {Type: "string", MinLength: metadataIntPointer(1)},
			}},
			"display": {Type: "object", AdditionalProperties: metadataBoolPointer(false), Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
				"title_field": {Type: "string", MinLength: metadataIntPointer(1)},
			}},
		},
	}
	return authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: metadataBoolPointer(false), Required: []string{"key", "name"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"key":                     metadataNonEmptyStringSchema("Stable lowercase object key matching the resourceKey path."),
			"name":                    metadataNonEmptyStringSchema("Human-readable object name."),
			"description":             {Type: "string"},
			"capabilities":            capabilities,
			"fields":                  {Type: "array", Items: &authoringcontract.CapabilityAuthoringSchema{Type: "object", AdditionalProperties: metadataBoolPointer(false)}, Default: []any{}},
			"lifecycle_policy":        lifecyclePolicy,
			"ledger_policy":           ledgerPolicy,
			"export_assurance_policy": exportAssurancePolicy,
			"ux":                      ux,
		},
	}
}

func metadataFieldPayloadSchema(fieldTypes []string) authoringcontract.CapabilityAuthoringSchema {
	values := make([]any, len(fieldTypes))
	for index, value := range fieldTypes {
		values[index] = value
	}
	config := authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: metadataBoolPointer(false),
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"precision":     {Type: "integer", Minimum: metadataFloatPointer(1), Maximum: metadataFloatPointer(38), Default: 19},
			"scale":         {Type: "integer", Minimum: metadataFloatPointer(0), Maximum: metadataFloatPointer(38), Default: 2},
			"rounding_mode": {Type: "string", Enum: []any{"ceiling", "down", "floor", "half_even", "half_up", "up"}, Default: "half_even"},
			"currency_code": {Type: "string", Format: "iso-4217", Default: "XXX"},
			"target":        {Type: "string"}, "cardinality": {Type: "string", Enum: []any{"many_to_one", "one_to_one"}, Default: "many_to_one"},
			"on_delete": {Type: "string", Enum: []any{"cascade", "restrict", "set_null"}, Default: "restrict"}, "inverse_name": {Type: "string"}, "indexed": {Type: "boolean", Default: true},
		},
	}
	return authoringcontract.CapabilityAuthoringSchema{
		Type: "object", AdditionalProperties: metadataBoolPointer(false), Required: []string{"key", "name", "type"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"key": metadataNonEmptyStringSchema("Stable field key."), "name": metadataNonEmptyStringSchema("Human-readable field name."), "description": {Type: "string"},
			"type": {Type: "string", Enum: values}, "required": {Type: "boolean", Default: false}, "unique": {Type: "boolean", Default: false},
			"default": {}, "default_value": {}, "config": config,
		},
	}
}

func metadataRelationPayloadSchema() authoringcontract.CapabilityAuthoringSchema {
	payload := metadataFieldPayloadSchema([]string{"relation"})
	payload.Required = append(payload.Required, "config")
	config := payload.Properties["config"]
	config.Required = []string{"target"}
	payload.Properties["config"] = config
	return payload
}

func metadataAuthoringExecution(resource string) *authoringcontract.CapabilityAuthoringExecution {
	return &authoringcontract.CapabilityAuthoringExecution{
		ReadSet: []string{"metadata.schema_snapshot", resource}, WriteSet: []string{"metadata.definition_version", resource},
		Transaction: "metadata_repository_transaction", Idempotency: "builder_task_id_and_idempotency_key",
		SideEffects: []string{"audit:metadata_definition.saved", "schema_snapshot_rebuild"}, SideEffectLevel: "internal", Compensation: "restore_prior_version_as_new_revision", PermissionModel: authoringcontract.CapabilityPermissionModelExactAction,
		ChangeControl: "direct_audited_versioned_metadata",
	}
}

func metadataConfigurationRoutes(resourceType string) []string {
	base := "/tenant-admin/metadata/definitions/" + resourceType + "/{resourceKey}"
	return []string{
		"GET " + base,
		"GET " + base + "/versions",
		"POST " + base + "/validate",
		"PUT " + base,
		"DELETE " + base,
		"POST " + base + "/rollback",
	}
}

// VersionedMetadataDefinitionAction resolves a concrete authoring projection
// back to the canonical, non-HTTP metadata use-case Action. Runtime may expose
// the generic HTTP endpoint with a concrete resource type in capability
// OpenAPI, but Identity authorization remains attached to these exact Actions.
func VersionedMetadataDefinitionAction(pattern string) (string, bool) {
	method, path, found := strings.Cut(strings.TrimSpace(pattern), " ")
	if !found {
		return "", false
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	const prefix = "/tenant-admin/metadata/definitions/"
	remaining := strings.TrimPrefix(strings.TrimSpace(path), prefix)
	if remaining == path {
		return "", false
	}
	segments := strings.Split(remaining, "/")
	if len(segments) < 2 || len(segments) > 3 || strings.TrimSpace(segments[0]) == "" ||
		!strings.HasPrefix(segments[1], "{") || !strings.HasSuffix(segments[1], "}") {
		return "", false
	}
	operation := ""
	if len(segments) == 3 {
		operation = strings.TrimSpace(segments[2])
	}
	switch {
	case method == "GET" && operation == "":
		return MetadataActionDefinitionGet, true
	case method == "GET" && operation == "versions":
		return MetadataActionDefinitionVersions, true
	case method == "POST" && operation == "validate":
		return MetadataActionDefinitionValidate, true
	case method == "PUT" && operation == "":
		return MetadataActionDefinitionUpsert, true
	case method == "DELETE" && operation == "":
		return MetadataActionDefinitionDisable, true
	case method == "POST" && operation == "rollback":
		return MetadataActionDefinitionRollback, true
	default:
		return "", false
	}
}

func metadataResourceOperations(resourceType string) *authoringcontract.CapabilityAuthoringResourceOperations {
	base := "/tenant-admin/metadata/definitions/" + resourceType + "/{resourceKey}"
	return &authoringcontract.CapabilityAuthoringResourceOperations{
		PersistenceMode: "audited_versioned_resource",
		Validate:        "POST " + base + "/validate",
		Upsert:          "PUT " + base,
		UpsertHeaders:   authoringcontract.DirectAuthoringUpsertHeaders(),
		SuccessSchema:   authoringcontract.DirectAuthoringSuccessSchema(),
		Get:             "GET " + base,
		Versions:        "GET " + base + "/versions",
		Rollback:        "POST " + base + "/rollback",
		Delete:          "DELETE " + base,
	}
}

func VersionedMetadataDefinitionRequestSchema(payload authoringcontract.CapabilityAuthoringSchema, objectKeyRequired bool) *authoringcontract.CapabilityAuthoringSchema {
	return metadataAuthoringRequestSchema(payload, objectKeyRequired)
}

func VersionedMetadataDefinitionOutputSchema(payload authoringcontract.CapabilityAuthoringSchema) *authoringcontract.CapabilityAuthoringSchema {
	return metadataAuthoringOutputSchema(payload)
}

func VersionedMetadataDefinitionRoutes(resourceType string) []string {
	return metadataConfigurationRoutes(resourceType)
}

func VersionedMetadataDefinitionOperations(resourceType string) *authoringcontract.CapabilityAuthoringResourceOperations {
	return metadataResourceOperations(resourceType)
}

func VersionedMetadataDefinitionExecution(resource string) *authoringcontract.CapabilityAuthoringExecution {
	return metadataAuthoringExecution(resource)
}

func metadataObjectReference(pointer string) authoringcontract.CapabilityAuthoringReference {
	return authoringcontract.CapabilityAuthoringReference{Kind: "object_key", InputJSONPointer: pointer, ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/object_key"}
}

func metadataRelationTargetReference(pointer string) authoringcontract.CapabilityAuthoringReference {
	return authoringcontract.CapabilityAuthoringReference{Kind: "relation_target_object_key", InputJSONPointer: pointer, ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/relation_target_object_key"}
}

func metadataStringSchema(description string) authoringcontract.CapabilityAuthoringSchema {
	return authoringcontract.CapabilityAuthoringSchema{Type: "string", Description: description}
}

func metadataNonEmptyStringSchema(description string) authoringcontract.CapabilityAuthoringSchema {
	return authoringcontract.CapabilityAuthoringSchema{Type: "string", MinLength: metadataIntPointer(1), Description: description}
}

func metadataBoolPointer(value bool) *bool { return &value }
