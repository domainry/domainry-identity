package policy

import (
	"github.com/domainry/domainry-foundation/apperror"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type ChangePlanBusinessRollbackPolicy struct {
	Version   string                                     `json:"version"`
	Resources []ChangePlanBusinessResourceRollbackPolicy `json:"resources"`
}

type ChangePlanBusinessResourceRollbackPolicy struct {
	ResourceTypes        []string `json:"resource_types"`
	Strategy             string   `json:"strategy"`
	PreservesRunEvidence bool     `json:"preserves_run_evidence"`
	SafetyChecks         []string `json:"safety_checks,omitempty"`
	Notes                string   `json:"notes"`
}

func ChangePlanBusinessMaintenanceRollbackPolicy(principal identitymodel.Principal) (ChangePlanBusinessRollbackPolicy, error) {
	if !principal.Known || !identitycontract.IdentityRoleHasPermissionKey(principal.Role, "workspace.admin") {
		return ChangePlanBusinessRollbackPolicy{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "auth.permission_denied"}
	}
	return ChangePlanBusinessRollbackPolicy{Version: "domain-rollback-policy-v1", Resources: []ChangePlanBusinessResourceRollbackPolicy{
		{ResourceTypes: []string{"object", "field", "validation", "view", "action", "identity_profile_binding", "surface"}, Strategy: "append_only_version", PreservesRunEvidence: true, SafetyChecks: []string{"reference_impact", "contract_compatibility"}, Notes: "Rollback creates a new Identity metadata version and never rewrites history."},
		{ResourceTypes: []string{"role", "permission", "menu", "data_scope", "field_permission"}, Strategy: "compensating_change_plan", PreservesRunEvidence: true, SafetyChecks: []string{"unique_administrator", "reference_impact"}, Notes: "Governance rollback is a reviewed compensating plan and cannot remove the last active administrator."},
	}}, nil
}
