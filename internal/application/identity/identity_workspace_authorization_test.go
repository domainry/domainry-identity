package identity

import (
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityApplicationAuthorizesWorkspaceBeforeRepositoryAccess(t *testing.T) {
	principal := identitymodel.Principal{Known: true}
	governance := NewIdentityGovernanceApplicationService(nil, nil, nil)
	if _, err := governance.Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{}, principal); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("governance validation error=%v", err)
	}
}
