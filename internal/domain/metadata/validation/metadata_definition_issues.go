package validation

import (
	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func NewMetadataDefinitionValidationIssue(code, fieldPath, stepKey, operationKey string, params map[string]string) metadatamodel.MetadataDefinitionValidationIssue {
	if strings.TrimSpace(fieldPath) == "" {
		fieldPath = MetadataDefinitionValidationErrorFieldPath(code, params)
	}
	return metadatamodel.MetadataDefinitionValidationIssue{
		FieldPath: fieldPath, StepKey: stepKey, OperationKey: operationKey, ErrorCode: code, MessageKey: code,
		CapabilityKey: metadataErrorCapabilityKey(code), ContractVersion: "identity-authoring.v1", Params: params,
	}
}

func metadataErrorCapabilityKey(code string) string {
	code = strings.TrimSpace(code)
	switch {
	case strings.Contains(code, "relation"):
		return "schema.relation"
	case strings.Contains(code, "field") || strings.Contains(code, "decimal"):
		return "schema.field"
	case strings.Contains(code, "role") || strings.Contains(code, "permission"):
		return "identity.role"
	case strings.Contains(code, "profile_binding"):
		return "identity.profile_binding"
	default:
		return "schema.object"
	}
}

func MetadataDefinitionValidationErrorFieldPath(code string, params map[string]string) string {
	switch code {
	case "backend.metadata.relation_target_required", "backend.metadata.relation_target_not_found":
		return "validation.target"
	case "backend.metadata.relation_cardinality_invalid":
		return "config.cardinality"
	case "backend.metadata.relation_on_delete_invalid", "backend.metadata.relation_set_null_required":
		return "config.on_delete"
	case "backend.metadata.relation_inverse_name_invalid":
		return "config.inverse_name"
	}
	return strings.TrimSpace(params["field"])
}
