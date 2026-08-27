package service

import (
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func onboardingDomainInput() (identitymodel.IdentityUser, identitymodel.Principal) {
	return identitymodel.IdentityUser{
			ID: " new-user ", Name: " New User ", Email: " NEW@EXAMPLE.TEST ", Status: identitymodel.IdentityStatusActive,
		}, identitymodel.Principal{
			Known: true, UserID: "manager",
			Role: identitymodel.RoleSchema{RecordScope: "all_records", GrantableRoleKeys: []string{"*"}},
		}
}

func TestPrepareWorkforceOnboardingNormalizesAndGovernsRoles(t *testing.T) {
	repository, service := identityRolesFixture()
	user, actor := onboardingDomainInput()
	prepared, assignments, err := service.PrepareWorkforceOnboarding(t.Context(), user, " workforce-1 ", []string{"viewer-id", "viewer-id"}, actor, " new hire ")
	if err != nil {
		t.Fatal(err)
	}
	if prepared.ID != "new-user" || prepared.Name != "New User" || prepared.Email != "new@example.test" ||
		len(assignments) != 1 || assignments[0].UserID != prepared.ID || assignments[0].WorkforceProfileID != "workforce-1" ||
		assignments[0].Source != "manual" || assignments[0].Status != "active" ||
		assignments[0].GrantedBy != actor.UserID || assignments[0].GrantReason != "new hire" {
		t.Fatalf("user=%#v assignments=%#v", prepared, assignments)
	}
	if err := ValidateNewIdentityWorkforceProfile(identitymodel.IdentityWorkforceProfile{}); apperror.CodeOf(err) != "backend.identity.workforce_profile_invalid" {
		t.Fatalf("expected shape validation error, got %v", err)
	}
	repository.roles = append(repository.roles, identitymodel.IdentityRole{ID: "legacy-id", Key: "legacy"})
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{})
	if _, legacy, err := service.PrepareWorkforceOnboarding(t.Context(), user, "workforce-1", []string{"legacy-id"}, actor, ""); err != nil || len(legacy) != 1 {
		t.Fatalf("legacy role onboarding failed: %#v, %v", legacy, err)
	}
}

func TestPrepareWorkforceOnboardingRejectsInvalidInputsAndRolePolicies(t *testing.T) {
	repository, service := identityRolesFixture()
	user, actor := onboardingDomainInput()
	tests := []struct {
		name    string
		profile string
		roleIDs []string
		actor   identitymodel.Principal
		defs    []identitymodel.RoleSchema
		roles   []identitymodel.IdentityRole
		code    string
	}{
		{name: "actor", profile: "workforce", actor: identitymodel.Principal{}, code: "backend.identity.entitlement_actor_required"},
		{name: "blank actor id", profile: "workforce", actor: identitymodel.Principal{Known: true, UserID: " "}, code: "backend.identity.entitlement_actor_required"},
		{name: "profile", profile: " ", actor: actor, code: "backend.identity.workforce_profile_invalid"},
		{name: "blank role", profile: "workforce", roleIDs: []string{" "}, actor: actor, code: "backend.identity.role_required"},
		{name: "missing role", profile: "workforce", roleIDs: []string{"missing"}, actor: actor, code: "backend.identity.role_not_found"},
		{name: "system role", profile: "workforce", roleIDs: []string{"custom"}, actor: actor, roles: []identitymodel.IdentityRole{{ID: "custom", Key: "custom"}}, defs: []identitymodel.RoleSchema{{Key: "custom", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged}}, code: "backend.identity.system_managed_role_assignment_denied"},
		{name: "request role", profile: "workforce", roleIDs: []string{"custom"}, actor: actor, roles: []identitymodel.IdentityRole{{ID: "custom", Key: "custom"}}, defs: []identitymodel.RoleSchema{{Key: "custom", AssignmentMode: identitymodel.IdentityRoleAssignmentRequestOnly}}, code: "backend.identity.role_request_required"},
		{name: "business role", profile: "workforce", roleIDs: []string{"custom"}, actor: actor, roles: []identitymodel.IdentityRole{{ID: "custom", Key: "custom"}}, defs: []identitymodel.RoleSchema{{Key: "custom", Audience: identitymodel.IdentityRoleAudienceBusiness}}, code: "backend.identity.workforce_role_eligibility_required"},
		{name: "privileged self grant", profile: "workforce", roleIDs: []string{"custom"}, actor: identitymodel.Principal{Known: true, UserID: "new-user", Role: actor.Role}, roles: []identitymodel.IdentityRole{{ID: "custom", Key: "custom"}}, defs: []identitymodel.RoleSchema{{Key: "custom", RiskLevel: identitymodel.IdentityRoleRiskPrivileged}}, code: "backend.identity.privileged_self_grant_denied"},
		{name: "privileged other without ceiling", profile: "workforce", roleIDs: []string{"custom"}, actor: identitymodel.Principal{Known: true, UserID: "manager", Role: identitymodel.RoleSchema{}}, roles: []identitymodel.IdentityRole{{ID: "custom", Key: "custom"}}, defs: []identitymodel.RoleSchema{{Key: "custom", Audience: identitymodel.IdentityRoleAudienceWorkforce, RiskLevel: identitymodel.IdentityRoleRiskPrivileged}}, code: "backend.identity.role_grant_ceiling_exceeded"},
		{name: "grant ceiling", profile: "workforce", roleIDs: []string{"custom"}, actor: identitymodel.Principal{Known: true, UserID: "manager", Role: identitymodel.RoleSchema{}}, roles: []identitymodel.IdentityRole{{ID: "custom", Key: "custom"}}, defs: []identitymodel.RoleSchema{{Key: "custom", RiskLevel: identitymodel.IdentityRoleRiskElevated}}, code: "backend.identity.role_grant_ceiling_exceeded"},
		{name: "conflict", profile: "workforce", roleIDs: []string{"left", "right"}, actor: actor, roles: []identitymodel.IdentityRole{{ID: "left", Key: "left"}, {ID: "right", Key: "right"}}, defs: []identitymodel.RoleSchema{{Key: "left", ConflictRoleKeys: []string{"right"}}, {Key: "right"}}, code: "backend.identity.role_conflict"},
		{name: "reverse conflict", profile: "workforce", roleIDs: []string{"left", "right"}, actor: actor, roles: []identitymodel.IdentityRole{{ID: "left", Key: "left"}, {ID: "right", Key: "right"}}, defs: []identitymodel.RoleSchema{{Key: "left"}, {Key: "right", ConflictRoleKeys: []string{"left"}}}, code: "backend.identity.role_conflict"},
	}
	originalRoles := append([]identitymodel.IdentityRole(nil), repository.roles...)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository.roles = append(append([]identitymodel.IdentityRole(nil), originalRoles...), test.roles...)
			if test.defs != nil {
				service.ReplaceRoleDefinitions(test.defs)
			} else {
				service.ReplaceRoleDefinitions(nil)
			}
			_, _, err := service.PrepareWorkforceOnboarding(t.Context(), user, test.profile, test.roleIDs, test.actor, "")
			if apperror.CodeOf(err) != test.code {
				t.Fatalf("expected %s, got %v", test.code, err)
			}
		})
	}
	repository.roles = append(originalRoles, identitymodel.IdentityRole{ID: "specific", Key: "specific"})
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "specific", Audience: identitymodel.IdentityRoleAudienceWorkforce, RiskLevel: identitymodel.IdentityRoleRiskElevated}})
	specificActor := actor
	specificActor.Role.GrantableRoleKeys = []string{"specific"}
	if _, assignments, err := service.PrepareWorkforceOnboarding(t.Context(), user, "workforce", []string{"specific"}, specificActor, ""); err != nil || len(assignments) != 1 {
		t.Fatalf("specific grant assignments=%+v err=%v", assignments, err)
	}
	repository.roles = append(repository.roles,
		identitymodel.IdentityRole{ID: "wildcard", Key: "wildcard"},
		identitymodel.IdentityRole{ID: "plain", Key: "plain"},
	)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "wildcard", RiskLevel: identitymodel.IdentityRoleRiskElevated},
		{Key: "plain"},
	})
	if _, assignments, err := service.PrepareWorkforceOnboarding(t.Context(), user, "workforce", []string{"wildcard", "plain"}, actor, ""); err != nil || len(assignments) != 2 {
		t.Fatalf("wildcard non-conflicting assignments=%+v err=%v", assignments, err)
	}
	repository.roles = originalRoles
	repository.listRolesErr = errIdentityRolesRepository
	if _, _, err := service.PrepareWorkforceOnboarding(t.Context(), user, "workforce", []string{"viewer-id"}, actor, ""); err != errIdentityRolesRepository {
		t.Fatalf("expected role repository error, got %v", err)
	}
}

func TestPrepareWorkforceOnboardingPropagatesUserPreparationFailure(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.listUsersErr = errIdentityRolesRepository
	user, actor := onboardingDomainInput()
	if _, _, err := service.PrepareWorkforceOnboarding(t.Context(), user, "workforce", nil, actor, ""); err != errIdentityRolesRepository {
		t.Fatalf("expected user preparation error, got %v", err)
	}
}
