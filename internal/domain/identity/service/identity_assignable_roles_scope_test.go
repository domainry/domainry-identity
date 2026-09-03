package service

import (
	"testing"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityListAssignableRolesUsesExactScopedTargetReads(t *testing.T) {
	repository, service := identityRolesFixture()
	owner := identitymodel.Principal{
		Known:  true,
		UserID: "user-1",
		Role: identitymodel.RoleSchema{Permissions: identityTestScopedRolePermissions(
			identitymodel.IdentityDataScopeOwner,
			identitycontract.IdentityUserRoleAssignmentsAssignableRolesPermission,
		)},
	}

	roles, err := service.ListAssignableRoles(t.Context(), "user-1", owner)
	if err != nil || len(roles) == 0 {
		t.Fatalf("owner assignable roles=%#v err=%v", roles, err)
	}
	if repository.listAssignmentsCalls != 0 || repository.listScopedAssignmentsCalls != 1 || repository.lastScopedAssignmentUserID != "user-1" {
		t.Fatalf("assignable-role lookup escaped scoped target read: unscoped=%d scoped=%d target=%q", repository.listAssignmentsCalls, repository.listScopedAssignmentsCalls, repository.lastScopedAssignmentUserID)
	}

	outsider := owner
	outsider.UserID = "other-user"
	roles, err = service.ListAssignableRoles(t.Context(), "user-1", outsider)
	if err != nil || len(roles) != 0 {
		t.Fatalf("out-of-scope assignable roles=%#v err=%v", roles, err)
	}
	if repository.listScopedAssignmentsCalls != 1 {
		t.Fatalf("out-of-scope target reached assignment lookup: scoped=%d", repository.listScopedAssignmentsCalls)
	}
}
