package validation

import (
	"regexp"
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

var actionPermissionKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$`)

// ActionPermissionKeyWellFormed reports whether an Action/Permission key is
// shaped as at least two dot-separated lower_snake_case segments.
func ActionPermissionKeyWellFormed(permission string) bool {
	return actionPermissionKeyPattern.MatchString(strings.TrimSpace(permission))
}

func actionValidatePermissionPolicy(action definitionmodel.ActionSchema) []metadatamodel.MetadataDefinitionValidationIssue {
	permission := strings.TrimSpace(action.Key)
	if permission == "" {
		return nil
	}
	issue := func(code string, params map[string]string) metadatamodel.MetadataDefinitionValidationIssue {
		return actionDefinitionValidationIssue(code, "key", params)
	}
	if !actionPermissionKeyPattern.MatchString(permission) {
		return []metadatamodel.MetadataDefinitionValidationIssue{issue("backend.action.permission_format_invalid", map[string]string{
			"field": "key", "actual": permission, "expected": "<object_key>.<action_name>",
		})}
	}
	objectKey := strings.TrimSpace(action.ObjectKey)
	if objectKey != "" && !strings.HasPrefix(permission, objectKey+".") {
		return []metadatamodel.MetadataDefinitionValidationIssue{issue("backend.action.permission_object_mismatch", map[string]string{
			"field": "key", "actual": permission, "object_key": objectKey,
		})}
	}
	issues := make([]metadatamodel.MetadataDefinitionValidationIssue, 0, 2)
	declaredRisk := strings.TrimSpace(action.RiskLevel)
	if declaredRisk != "" && identitycontract.IdentityActionRiskLevelRank(declaredRisk) == 0 {
		issues = append(issues, actionDefinitionValidationIssue("backend.action.risk_level_invalid", "risk_level", map[string]string{
			"field": "risk_level", "actual": declaredRisk, "allowed": strings.Join(identitycontract.IdentityActionRiskLevels(), ","),
		}))
	}
	inferredAction := action
	inferredAction.RiskLevel = ""
	inferredRisk := identitycontract.IdentityActionRiskLevel(inferredAction)
	if declaredRisk != "" && identitycontract.IdentityActionRiskLevelRank(declaredRisk) > 0 && identitycontract.IdentityActionRiskLevelRank(declaredRisk) < identitycontract.IdentityActionRiskLevelRank(inferredRisk) {
		issues = append(issues, actionDefinitionValidationIssue("backend.action.risk_level_understated", "risk_level", map[string]string{
			"field": "risk_level", "actual": declaredRisk, "minimum": inferredRisk,
		}))
	}
	riskLevel := identitycontract.IdentityActionRiskLevel(action)
	if riskLevel == "high" || riskLevel == "critical" {
		if !identitycontract.IdentityActionHasEnhancedAssurance(action) {
			issues = append(issues, actionDefinitionValidationIssue("backend.action.high_risk_assurance_required", "assurance_policy.required_methods", map[string]string{
				"field": "assurance_policy.required_methods", "action": strings.TrimSpace(action.Key),
			}))
		}
	}
	return issues
}
