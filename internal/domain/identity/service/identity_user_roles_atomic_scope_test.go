package service

import (
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestUpsertUserWithRolesRejectsForgedRequestOrganizationScope(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.users = []identitymodel.IdentityUser{{
		ID: "user-1", Name: "Existing", Email: "existing@example.com", AccountType: identitymodel.IdentityAccountHuman,
		OrgID: "outside", Status: identitymodel.IdentityStatusActive, Version: 4,
	}}
	actor := identitymodel.Principal{
		Known: true, UserID: "manager", OrgScopeIDs: []string{"organizationUnit"},
		Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(
			identitymodel.IdentityDataScopeOrgChild,
			identitycontract.IdentityUserRoleAssignmentsAccountUpdatePermission,
		)},
	}
	request := identitymodel.IdentityUser{
		ID: "user-1", Name: "Existing", Email: "existing@example.com", AccountType: identitymodel.IdentityAccountHuman,
		OrgID: "organizationUnit", Status: identitymodel.IdentityStatusActive, Version: 4,
	}

	err := service.UpsertUserWithRoles(t.Context(), request, nil, actor)
	if apperror.CodeOf(err) != "backend.identity.data_scope_denied" {
		t.Fatalf("forged request organization authorized: err=%v", err)
	}
	if repository.reconciledUser.ID != "" {
		t.Fatalf("unauthorized target was persisted: %#v", repository.reconciledUser)
	}
}
