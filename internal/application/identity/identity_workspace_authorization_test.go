package identity

import (
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityApplicationAuthorizesWorkspaceBeforeRepositoryAccess(t *testing.T) {
	principal := identitymodel.Principal{Known: true}
	service := NewIdentityApplicationService(nil, nil)
	if _, err := service.GovernanceSnapshot(t.Context(), principal); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("snapshot error=%v", err)
	}
	if _, err := service.EnrichBusinessReferenceGraph(t.Context(), changeplanmodel.ReferenceGraph{}, principal); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("reference graph error=%v", err)
	}
	governance := NewIdentityGovernanceApplicationService(nil, nil, nil)
	if _, err := governance.Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{}, principal); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("governance validation error=%v", err)
	}
}
