package policy

import (
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestChangePlanBusinessRollbackPolicyPreservesExecutionEvidenceAndAdministratorSafety(t *testing.T) {
	policy, err := ChangePlanBusinessMaintenanceRollbackPolicy(identitymodel.Principal{Known: true, UserID: "admin", Role: identitymodel.RoleSchema{Key: "admin", Permissions: []string{"workspace.admin"}}})
	if err != nil {
		t.Fatal(err)
	}
	foundMetadata, foundGovernance := false, false
	for _, resource := range policy.Resources {
		if !resource.PreservesRunEvidence {
			t.Fatalf("rollback policy may not discard execution evidence: %#v", resource)
		}
		for _, resourceType := range resource.ResourceTypes {
			switch resourceType {
			case "field":
				foundMetadata = resource.Strategy == "append_only_version"
			case "role":
				for _, check := range resource.SafetyChecks {
					foundGovernance = foundGovernance || check == "unique_administrator"
				}
			}
		}
	}
	if !foundMetadata || !foundGovernance {
		t.Fatalf("rollback policy is incomplete: %#v", policy)
	}
}

func TestChangePlanBusinessRollbackPolicyRequiresKnownWorkspaceAdministrator(t *testing.T) {
	for _, principal := range []identitymodel.Principal{{}, {Known: true, Role: identitymodel.RoleSchema{Permissions: []string{"workspace.read"}}}} {
		policy, err := ChangePlanBusinessMaintenanceRollbackPolicy(principal)
		if apperror.CodeOf(err) != "auth.permission_denied" || policy.Version != "" || policy.Resources != nil {
			t.Fatalf("unauthorized policy = %#v, err=%v", policy, err)
		}
	}
}
