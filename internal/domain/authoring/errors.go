package authoring

import "strings"

type CapabilityAuthoringErrorContract struct {
	CapabilityKey   string `json:"capability_key,omitempty"`
	ContractVersion string `json:"contract_version"`
	FieldPath       string `json:"field_path,omitempty"`
}

func RuntimeAuthoringErrorContract(code string, params map[string]string) CapabilityAuthoringErrorContract {
	result := CapabilityAuthoringErrorContract{ContractVersion: RuntimeAuthoringContractVersion, FieldPath: runtimeErrorFieldPath(params)}
	code = strings.TrimSpace(code)
	if code == "backend.metadata.definition_version_conflict" {
		result.CapabilityKey = metadataResourceCapabilityKey(params["resource_type"])
		return result
	}
	result.CapabilityKey = fallbackAuthoringErrorCapability(code)
	return result
}

func fallbackAuthoringErrorCapability(code string) string {
	switch {
	case strings.HasPrefix(code, "backend.action."):
		return "action.definition"
	case strings.HasPrefix(code, "backend.change_plan."):
		return "maintenance.change_plan_validation"
	case strings.HasPrefix(code, "backend.identity.department") || strings.HasPrefix(code, "backend.identity.parent_department"):
		return "identity.department"
	case strings.HasPrefix(code, "backend.identity.user"):
		return "identity.user"
	case strings.HasPrefix(code, "backend.identity.menu"):
		return "identity.menu"
	case strings.HasPrefix(code, "backend.identity."):
		return "identity.role"
	default:
		return ""
	}
}

func metadataResourceCapabilityKey(resourceType string) string {
	switch strings.TrimSpace(resourceType) {
	case "field":
		return "schema.field"
	case "action":
		return "action.definition"
	default:
		return ""
	}
}

func runtimeErrorFieldPath(params map[string]string) string {
	for _, key := range []string{"field_path", "field", "parameter_path", "path"} {
		if value := strings.TrimSpace(params[key]); value != "" {
			return value
		}
	}
	return ""
}
