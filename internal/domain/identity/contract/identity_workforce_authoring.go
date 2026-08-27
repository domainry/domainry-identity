package contract

import (
	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
)

func IdentityWorkforceProfileAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed := identityBoolPointer(false)
	input := &authoringcontract.CapabilityAuthoringSchema{
		Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed,
		Required: []string{"id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"id": {Type: "string", MinLength: identityIntPointer(1)}, "organization_id": {Type: "string", MinLength: identityIntPointer(1)},
			"identity_user_id": {Type: "string", MinLength: identityIntPointer(1)}, "worker_no": {Type: "string", MinLength: identityIntPointer(1)},
			"worker_type": {Type: "string", Enum: []any{"employee", "contractor", "partner_staff", "temporary"}},
			"work_status": {Type: "string", Enum: []any{"pending", "active", "suspended", "terminated"}},
			"start_date":  {Type: "string", Format: "date"}, "end_date": {Type: "string", Format: "date"},
			"primary_assignment_id": {Type: "string"}, "version": {Type: "integer"},
		},
	}
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.workforce_profile", Status: "supported", Lifecycle: "immediate_audited_configuration", Requires: []string{"identity.user"},
		Parameters: []authoringcontract.CapabilityAuthoringParameter{
			{Key: "id", Type: "string", Required: true}, {Key: "organization_id", Type: "string", Required: true},
			{Key: "identity_user_id", Type: "string", Required: true}, {Key: "worker_no", Type: "string", Required: true},
			{Key: "worker_type", Type: "string", Required: true, Enum: []string{"employee", "contractor", "partner_staff", "temporary"}},
			{Key: "work_status", Type: "string", Required: true, Enum: []string{"pending", "active", "suspended", "terminated"}},
			{Key: "start_date", Type: "string", Format: "date"}, {Key: "end_date", Type: "string", Format: "date"},
			{Key: "primary_assignment_id", Type: "string"}, {Key: "version", Type: "integer"},
		},
		Permissions: []string{"identity.workforce.write"}, AuditEvents: []string{"identity_workforce_profile_upserted"},
		ValidationEndpoint:       "POST /identity/workforce/{profileID}/validate",
		ConfigurationRoutes:      []string{"POST /identity/workforce", "PATCH /identity/workforce/{profileID}", "GET /identity/workforce/{profileID}"},
		ResourceKeyPathParameter: "profileID",
		InputSchema:              input, OutputSchema: input,
		OutputVariables:    []authoringcontract.CapabilityAuthoringOutput{{Name: "workforce_profile_id", JSONPointer: "/id", Type: "workforce_profile_id", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{{Kind: "user_id", InputJSONPointer: "/identity_user_id", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/user_id"}},
		Execution:          identityManagementExecution([]string{"identity.user", "identity.workforce_profile"}, "identity.workforce_profile", "stable_workforce_profile_id_upsert", "identity_workforce_profile_upserted", "identity.workforce.write"),
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.identity.workforce_profile_invalid", FieldPath: "id", MessageKey: "backend.identity.workforce_profile_invalid"},
			{Code: "backend.identity.workforce_user_not_found", FieldPath: "identity_user_id", MessageKey: "backend.identity.workforce_user_not_found"},
			{Code: "backend.identity.workforce_worker_type_invalid", FieldPath: "worker_type", MessageKey: "backend.identity.workforce_worker_type_invalid"},
			{Code: "backend.identity.workforce_status_invalid", FieldPath: "work_status", MessageKey: "backend.identity.workforce_status_invalid"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"id": "worker-1", "organization_id": "default", "identity_user_id": "user-1", "worker_no": "E-001", "worker_type": "employee", "work_status": "active"}},
			{Name: "representative", Value: map[string]any{"id": "worker-2", "organization_id": "default", "identity_user_id": "user-2", "worker_no": "C-001", "worker_type": "contractor", "work_status": "active", "start_date": "2026-07-25"}},
			{Name: "invalid_with_repair", Value: map[string]any{"id": "worker-1", "organization_id": "default", "identity_user_id": "missing", "worker_no": "E-001", "worker_type": "employee", "work_status": "active"}, ExpectedErrorCodes: []string{"backend.identity.workforce_user_not_found"}},
		},
		Sources: identityWorkforceAuthoringSources("IdentityWorkforceProfile", "IdentityWorkforceDomainService.UpsertProfile"),
	}
}

func IdentityWorkforceAssignmentAuthoringCapability() authoringcontract.CapabilityAuthoringDefinition {
	closed := identityBoolPointer(false)
	input := &authoringcontract.CapabilityAuthoringSchema{
		Schema: "https://json-schema.org/draft/2020-12/schema", Type: "object", AdditionalProperties: closed,
		Required: []string{"id", "workforce_profile_id", "organization_unit_id", "assignment_type", "status"},
		Properties: map[string]authoringcontract.CapabilityAuthoringSchema{
			"id": {Type: "string", MinLength: identityIntPointer(1)}, "workforce_profile_id": {Type: "string", MinLength: identityIntPointer(1)},
			"organization_unit_id": {Type: "string", MinLength: identityIntPointer(1)}, "position_id": {Type: "string"},
			"manager_workforce_profile_id": {Type: "string"},
			"assignment_type":              {Type: "string", Enum: []any{"primary", "secondary", "temporary", "acting"}},
			"effective_from":               {Type: "string", Format: "date"}, "effective_to": {Type: "string", Format: "date"},
			"status": {Type: "string", Enum: []any{"active", "disabled"}}, "version": {Type: "integer"},
		},
	}
	return authoringcontract.CapabilityAuthoringDefinition{
		Key: "identity.workforce_assignment", Status: "supported", Lifecycle: "immediate_audited_configuration", Requires: []string{"identity.workforce_profile", "identity.department"},
		Parameters: []authoringcontract.CapabilityAuthoringParameter{
			{Key: "id", Type: "string", Required: true}, {Key: "workforce_profile_id", Type: "string", Required: true},
			{Key: "organization_unit_id", Type: "string", Required: true}, {Key: "position_id", Type: "string"},
			{Key: "manager_workforce_profile_id", Type: "string"}, {Key: "assignment_type", Type: "string", Required: true, Enum: []string{"primary", "secondary", "temporary", "acting"}},
			{Key: "effective_from", Type: "string", Format: "date"}, {Key: "effective_to", Type: "string", Format: "date"},
			{Key: "status", Type: "string", Required: true, Enum: []string{"active", "disabled"}}, {Key: "version", Type: "integer"},
		},
		Permissions: []string{"identity.workforce.write"}, AuditEvents: []string{"identity_workforce_assignment_upserted"},
		ValidationEndpoint:       "POST /identity/workforce/{profileID}/assignments/validate",
		ConfigurationRoutes:      []string{"POST /identity/workforce/{profileID}/assignments", "GET /identity/workforce/{profileID}/assignments"},
		ResourceKeyPathParameter: "profileID",
		InputSchema:              input, OutputSchema: input,
		OutputVariables: []authoringcontract.CapabilityAuthoringOutput{{Name: "workforce_assignment_id", JSONPointer: "/id", Type: "workforce_assignment_id", VisibleTo: "subsequent_capability_calls"}},
		ReferenceContracts: []authoringcontract.CapabilityAuthoringReference{
			{Kind: "workforce_profile_id", InputJSONPointer: "/workforce_profile_id", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/workforce_profile_id"},
			{Kind: "department_id", InputJSONPointer: "/organization_unit_id", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/department_id"},
			{Kind: "workforce_profile_id", InputJSONPointer: "/manager_workforce_profile_id", ResolverEndpoint: "GET /tenant-admin/platform-capabilities/references/workforce_profile_id"},
		},
		Execution: identityManagementExecution([]string{"identity.workforce_profile", "identity.workforce_assignment", "identity.department"}, "identity.workforce_assignment", "stable_workforce_assignment_id_upsert", "identity_workforce_assignment_upserted", "identity.workforce.write"),
		Errors: []authoringcontract.CapabilityAuthoringError{
			{Code: "backend.identity.workforce_assignment_invalid", FieldPath: "id", MessageKey: "backend.identity.workforce_assignment_invalid"},
			{Code: "backend.identity.workforce_profile_not_found", FieldPath: "workforce_profile_id", MessageKey: "backend.identity.workforce_profile_not_found"},
			{Code: "backend.identity.workforce_primary_assignment_conflict", FieldPath: "effective_from", MessageKey: "backend.identity.workforce_primary_assignment_conflict"},
			{Code: "backend.identity.workforce_manager_invalid", FieldPath: "manager_workforce_profile_id", MessageKey: "backend.identity.workforce_manager_invalid"},
		},
		Examples: []authoringcontract.CapabilityAuthoringExample{
			{Name: "minimal_valid", Value: map[string]any{"id": "assignment-1", "workforce_profile_id": "worker-1", "organization_unit_id": "sales", "assignment_type": "primary", "status": "active"}},
			{Name: "representative", Value: map[string]any{"id": "assignment-2", "workforce_profile_id": "worker-1", "organization_unit_id": "store-east", "assignment_type": "temporary", "effective_from": "2026-07-25", "effective_to": "2026-08-01", "status": "active"}},
			{Name: "invalid_with_repair", Value: map[string]any{"id": "assignment-2", "workforce_profile_id": "missing", "organization_unit_id": "sales", "assignment_type": "primary", "status": "active"}, ExpectedErrorCodes: []string{"backend.identity.workforce_profile_not_found"}},
		},
		Sources: identityWorkforceAuthoringSources("IdentityWorkforceAssignment", "IdentityWorkforceDomainService.UpsertAssignment"),
	}
}

func identityWorkforceAuthoringSources(modelSymbol, validationSymbol string) []authoringcontract.CapabilityAuthoringSource {
	return []authoringcontract.CapabilityAuthoringSource{
		{Kind: "contract", Path: "internal/domain/identity/contract/identity_workforce_authoring.go"},
		{Kind: "model", Path: "internal/domain/identity/model/identity_workforce.go", Symbol: modelSymbol},
		{Kind: "validation", Path: "internal/domain/identity/service/identity_workforce_domain_service.go", Symbol: validationSymbol},
		{Kind: "http", Path: "internal/transport/http/identity/identity_routes.go", Symbol: "RegisterRoutes"},
	}
}
