package service

import (
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestManualServiceRoleRequiresActiveServiceAccount(t *testing.T) {
	repository, domain := identityRolesFixture()
	repository.roles = append(repository.roles, identitymodel.IdentityRole{
		RoleID: "open-api-id", Key: "open_api_service", Label: "Open API", Status: identitymodel.IdentityStatusActive,
	})
	repository.users = append(repository.users,
		identitymodel.IdentityUser{UserID: "service-1", AccountType: identitymodel.IdentityAccountService, Status: identitymodel.IdentityStatusActive},
		identitymodel.IdentityUser{UserID: "human-1", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive},
		identitymodel.IdentityUser{UserID: "disabled-service", AccountType: identitymodel.IdentityAccountService, Status: identitymodel.IdentityStatusDisabled},
	)
	domain.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "open_api_service", Name: "Open API", Audience: identitymodel.IdentityRoleAudienceService,
		AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
	}})

	if err := domain.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "service-1", RoleID: "open-api-id"}); err != nil {
		t.Fatalf("assign service role to service account: %v", err)
	}
	for _, userID := range []string{"human-1", "disabled-service"} {
		err := domain.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: userID, RoleID: "open-api-id"})
		if apperror.CodeOf(err) != "backend.identity.service_role_account_type_required" {
			t.Fatalf("user %q received service role: %v", userID, err)
		}
	}
}
