package contract

import (
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
)

func IdentityActionAssuranceMethods(action definitionmodel.ActionSchema) []string {
	if action.AssurancePolicy == nil {
		return nil
	}
	return action.AssurancePolicy.RequiredMethods
}

func IdentityActionApprovalRequired(action definitionmodel.ActionSchema) bool {
	for _, method := range IdentityActionAssuranceMethods(action) {
		if method == definitionmodel.ActionAssuranceMakerChecker || method == definitionmodel.ActionAssuranceWorkflowApproval {
			return true
		}
	}
	return false
}

func IdentityActionRiskLevels() []string { return []string{"low", "medium", "high", "critical"} }

func IdentityActionRiskLevelRank(value string) int {
	switch strings.TrimSpace(value) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

func IdentityActionRiskLevel(action definitionmodel.ActionSchema) string {
	inferred := identityActionInferredRiskLevel(action)
	declared := strings.TrimSpace(action.RiskLevel)
	if IdentityActionRiskLevelRank(declared) > IdentityActionRiskLevelRank(inferred) {
		return declared
	}
	return inferred
}

func identityActionInferredRiskLevel(action definitionmodel.ActionSchema) string {
	for _, method := range IdentityActionAssuranceMethods(action) {
		if method == definitionmodel.ActionAssuranceMakerChecker || method == definitionmodel.ActionAssuranceWorkflowApproval {
			return "critical"
		}
	}
	for _, method := range IdentityActionAssuranceMethods(action) {
		if method == definitionmodel.ActionAssuranceOTP || method == definitionmodel.ActionAssuranceRecentReauth {
			return "high"
		}
	}
	if action.Kind == "record_delete" {
		return "high"
	}
	if action.Kind == "record_update" || action.Kind == "record_operation" || action.Kind == "bulk_operation" {
		return "medium"
	}
	return "low"
}

func IdentityActionHasEnhancedAssurance(action definitionmodel.ActionSchema) bool {
	if IdentityActionApprovalRequired(action) {
		return true
	}
	for _, method := range IdentityActionAssuranceMethods(action) {
		switch method {
		case definitionmodel.ActionAssuranceRecentReauth, definitionmodel.ActionAssuranceOTP:
			return true
		}
	}
	return false
}
