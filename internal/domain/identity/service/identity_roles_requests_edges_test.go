package service

import (
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityRoleEligibilityRepositoryAndFallbackEdges(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.roles = append(repository.roles, identitymodel.IdentityRole{
		ID: "legacy-id", Key: "legacy", Label: "Legacy", Status: identitymodel.IdentityStatusActive,
	})
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{
		UserID: "user-1", RoleID: "legacy-id",
	}); err != nil {
		t.Fatalf("unpublished role fallback assignment: %v", err)
	}

	workforce := identitymodel.RoleSchema{Audience: identitymodel.IdentityRoleAudienceWorkforce}
	repository.err = errIdentityRolesRepository
	if err := service.validateManualRoleEligibility(t.Context(), identitymodel.IdentityUserRoleAssignment{
		UserID: "user-1", WorkforceProfileID: "workforce",
	}, workforce); err != errIdentityRolesRepository {
		t.Fatalf("workforce repository error=%v", err)
	}
	repository.err = nil

	business := identitymodel.RoleSchema{
		Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member",
	}
	service.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{err: errIdentityRolesRepository})
	if err := service.validateManualRoleEligibility(t.Context(), identitymodel.IdentityUserRoleAssignment{
		UserID: "user-1", BindingKey: "member", ProfileID: "profile",
	}, business); err != errIdentityRolesRepository {
		t.Fatalf("binding repository error=%v", err)
	}

	repository.listAssignmentsErr = errIdentityRolesRepository
	if err := service.validateRoleEligibility(t.Context(), identitymodel.IdentityUserRoleAssignment{
		UserID: "user-1",
	}, identitymodel.RoleSchema{}, true); err != errIdentityRolesRepository {
		t.Fatalf("assignment conflict lookup error=%v", err)
	}
	repository.listAssignmentsErr = nil
	repository.listRolesErr = errIdentityRolesRepository
	if err := service.validateRoleConflicts(t.Context(), "user-1", identitymodel.RoleSchema{}); err != errIdentityRolesRepository {
		t.Fatalf("role conflict lookup error=%v", err)
	}
}

func TestIdentityManualAssignmentSecondRoleLookupEdges(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "error", err: errIdentityRolesRepository},
		{name: "missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, service := identityRolesFixture()
			roles := append([]identitymodel.IdentityRole(nil), repository.roles...)
			repository.listRolesFunc = func(call int) ([]identitymodel.IdentityRole, error) {
				if call == 1 {
					return roles, nil
				}
				if test.err != nil {
					return nil, test.err
				}
				return nil, nil
			}
			err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{
				UserID: "user-1", RoleID: "member-id",
			})
			if test.err != nil && err != test.err {
				t.Fatalf("second lookup error=%v", err)
			}
			if test.err == nil && apperror.CodeOf(err) != "backend.identity.role_not_found" {
				t.Fatalf("second lookup missing error=%v", err)
			}
		})
	}
}

func TestIdentityRoleConflictSkipsInactiveAndUnknownAssignments(t *testing.T) {
	repository, service := identityRolesFixture()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{
		{UserID: "user-1", RoleID: "member-id", Status: "revoked"},
		{UserID: "user-1", RoleID: "member-id", Status: "active", ExpiresAt: &past},
		{UserID: "user-1", RoleID: "unknown", Status: "active"},
		{UserID: "user-1", RoleID: "member-id", Status: "active"},
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "member", ConflictRoleKeys: []string{"viewer"}},
		{Key: "viewer"},
	})
	if err := service.validateRoleConflicts(t.Context(), "user-1", identitymodel.RoleSchema{Key: "viewer"}); apperror.CodeOf(err) != "backend.identity.role_conflict" {
		t.Fatalf("reverse conflict error=%v", err)
	}
	if identityStringSliceContains([]string{" member "}, "other") {
		t.Fatal("unexpected string slice match")
	}
}

func TestIdentityAssignSystemManagedRoleFailureEdges(t *testing.T) {
	valid := identitymodel.IdentityUserRoleAssignment{
		UserID: "user-1", RoleID: "member-id", BindingKey: "member", ProfileID: "profile",
	}
	for _, test := range []struct {
		name  string
		setup func(*identityRolesRepositoryStub, *IdentityDomainService)
		code  string
		err   error
	}{
		{"role lookup", func(r *identityRolesRepositoryStub, _ *IdentityDomainService) {
			r.listRolesErr = errIdentityRolesRepository
		}, "", errIdentityRolesRepository},
		{"missing role", func(r *identityRolesRepositoryStub, _ *IdentityDomainService) { r.roles = nil }, "backend.identity.role_not_found", nil},
		{"unpublished role", func(_ *identityRolesRepositoryStub, s *IdentityDomainService) { s.ReplaceRoleDefinitions(nil) }, "backend.identity.system_managed_role_required", nil},
		{"invalid binding", func(_ *identityRolesRepositoryStub, s *IdentityDomainService) {
			s.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness, AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged, RequiredBindingKey: "other"}})
		}, "backend.identity.business_role_eligibility_required", nil},
		{"binding error", func(_ *identityRolesRepositoryStub, s *IdentityDomainService) {
			s.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness, AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged, RequiredBindingKey: "member"}})
			s.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{err: errIdentityRolesRepository})
		}, "", errIdentityRolesRepository},
		{"inactive binding", func(_ *identityRolesRepositoryStub, s *IdentityDomainService) {
			s.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness, AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged, RequiredBindingKey: "member"}})
			s.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{})
		}, "backend.identity.business_role_eligibility_required", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, service := identityRolesFixture()
			test.setup(repository, service)
			err := service.AssignSystemManagedRole(t.Context(), valid)
			if test.err != nil && err != test.err {
				t.Fatalf("error=%v", err)
			}
			if test.code != "" && apperror.CodeOf(err) != test.code {
				t.Fatalf("code=%q error=%v", apperror.CodeOf(err), err)
			}
		})
	}

	repository, service := identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness,
		AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged, RequiredBindingKey: "member",
	}})
	service.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{active: true})
	repository.listAssignmentsErr = errIdentityRolesRepository
	if err := service.AssignSystemManagedRole(t.Context(), valid); err != errIdentityRolesRepository {
		t.Fatalf("conflict lookup error=%v", err)
	}
}

func TestIdentityGovernedRoleRemovalFailureEdges(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.listRolesErr = errIdentityRolesRepository
	if err := service.RemoveUserRole(t.Context(), "user-1", "member-id"); err != errIdentityRolesRepository {
		t.Fatalf("role lookup error=%v", err)
	}

	repository, service = identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged,
	}})
	if err := service.RemoveUserRole(t.Context(), "user-1", "member-id"); apperror.CodeOf(err) != "backend.identity.system_managed_role_assignment_denied" {
		t.Fatalf("system role removal error=%v", err)
	}

	repository, service = identityRolesFixture()
	repository.listAssignmentsErr = errIdentityRolesRepository
	if err := service.RemoveUserRole(t.Context(), "user-1", "admin-id"); err != errIdentityRolesRepository {
		t.Fatalf("role assignment lookup error=%v", err)
	}
	repository, service = identityRolesFixture()
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{
		{UserID: "user-1", RoleID: "admin-id", Status: "active"},
	}
	if err := service.RemoveUserRole(t.Context(), "user-1", "admin-id"); err != nil || len(repository.assigned) != 1 || repository.assigned[0].Status != "revoked" {
		t.Fatalf("ordinary exact workspace capability revocation assignments=%+v err=%v", repository.assigned, err)
	}
	repository.assignErr = errIdentityRolesRepository
	if err := service.RemoveUserRoleGoverned(t.Context(), "user-1", "admin-id", "actor", ""); err != errIdentityRolesRepository {
		t.Fatalf("revocation write error=%v", err)
	}

	repository, service = identityRolesFixture()
	repository.listAssignmentsErr = errIdentityRolesRepository
	if err := service.RemoveUserRole(t.Context(), "user-1", "member-id"); err != errIdentityRolesRepository {
		t.Fatalf("assignment listing error=%v", err)
	}
	repository.listAssignmentsErr = nil
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{
		{UserID: "user-1", RoleID: "other", Status: "active"},
		{UserID: "user-1", RoleID: "member-id", Status: "active", ExpiresAt: &past},
	}
	repository.removeErr = errIdentityRolesRepository
	if err := service.RemoveUserRole(t.Context(), "user-1", "member-id"); err != errIdentityRolesRepository {
		t.Fatalf("physical removal error=%v", err)
	}
}

func TestIdentityListAssignableRolesFailureAndRiskEdges(t *testing.T) {
	actor := identitymodel.Principal{
		Known: true, UserID: "admin", Role: identitymodel.RoleSchema{RecordScope: "all_records"},
	}
	repository, service := identityRolesFixture()
	if _, err := service.ListAssignableRoles(t.Context(), " ", actor); apperror.CodeOf(err) != "backend.identity.user_required" {
		t.Fatalf("missing user error=%v", err)
	}
	repository.listUsersErr = errIdentityRolesRepository
	if _, err := service.ListAssignableRoles(t.Context(), "user-1", actor); err != errIdentityRolesRepository {
		t.Fatalf("user lookup error=%v", err)
	}
	repository.listUsersErr = nil
	if _, err := service.ListAssignableRoles(t.Context(), "missing", actor); apperror.CodeOf(err) != "backend.identity.user_not_found" {
		t.Fatalf("unknown user error=%v", err)
	}
	roles, err := service.ListAssignableRoles(t.Context(), "disabled-user", actor)
	if err != nil || len(roles) != 0 {
		t.Fatalf("disabled target roles=%v err=%v", roles, err)
	}

	repository.workforceErr = errIdentityRolesRepository
	if _, err := service.ListAssignableRoles(t.Context(), "user-1", actor); err != errIdentityRolesRepository {
		t.Fatalf("workforce facts error=%v", err)
	}
	repository.workforceErr = nil
	repository.profileBindingsErr = errIdentityRolesRepository
	if _, err := service.ListAssignableRoles(t.Context(), "user-1", actor); err != errIdentityRolesRepository {
		t.Fatalf("bindings error=%v", err)
	}
	repository.profileBindingsErr = nil
	repository.listRolesErr = errIdentityRolesRepository
	if _, err := service.ListAssignableRoles(t.Context(), "user-1", actor); err != errIdentityRolesRepository {
		t.Fatalf("roles error=%v", err)
	}

	repository, service = identityRolesFixture()
	repository.roles = []identitymodel.IdentityRole{{ID: "privileged", Key: "privileged", Label: "Privileged", Status: identitymodel.IdentityStatusActive}}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "privileged", AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
		RiskLevel: identitymodel.IdentityRoleRiskPrivileged,
	}})
	self := actor
	self.UserID = "user-1"
	self.Role.GrantableRoleKeys = []string{"*"}
	if roles, err = service.ListAssignableRoles(t.Context(), "user-1", self); err != nil || len(roles) != 0 {
		t.Fatalf("self privileged roles=%v err=%v", roles, err)
	}

	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "privileged", AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
		RiskLevel: identitymodel.IdentityRoleRiskElevated,
	}})
	repository.listAssignmentsErr = errIdentityRolesRepository
	actor.Role.GrantableRoleKeys = []string{"privileged"}
	if _, err := service.ListAssignableRoles(t.Context(), "user-1", actor); err != errIdentityRolesRepository {
		t.Fatalf("conflict lookup error=%v", err)
	}

	repository, service = identityRolesFixture()
	repository.roles = []identitymodel.IdentityRole{
		{ID: "business", Key: "business", Label: "Business", Status: identitymodel.IdentityStatusActive},
		{ID: "conflicting", Key: "conflicting", Label: "Conflicting", Status: identitymodel.IdentityStatusActive},
		{ID: "existing", Key: "existing", Label: "Existing", Status: identitymodel.IdentityStatusActive},
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "business", Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "conflicting", AssignmentMode: identitymodel.IdentityRoleAssignmentManual, ConflictRoleKeys: []string{"existing"}},
		{Key: "existing", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
	})
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{{
		UserID: "user-1", RoleID: "existing", Status: "active",
	}}
	if roles, err = service.ListAssignableRoles(t.Context(), "user-1", actor); err != nil || len(roles) != 1 || roles[0].Key != "existing" {
		t.Fatalf("filtered assignable roles=%v err=%v", roles, err)
	}
}

func TestIdentityRoleRequestRemainingShortCircuitOutcomes(t *testing.T) {
	t.Run("manual audience prerequisites", func(t *testing.T) {
		_, service := identityRolesFixture()
		if err := service.validateManualRoleEligibility(t.Context(), identitymodel.IdentityUserRoleAssignment{
			UserID: "user-1", WorkforceProfileID: "missing-profile",
		}, identitymodel.RoleSchema{Audience: identitymodel.IdentityRoleAudienceWorkforce}); apperror.CodeOf(err) != "backend.identity.workforce_role_eligibility_required" {
			t.Fatalf("missing workforce profile error=%v", err)
		}
		if err := service.validateManualRoleEligibility(t.Context(), identitymodel.IdentityUserRoleAssignment{
			UserID: "user-1", BindingKey: "member", ProfileID: "profile",
		}, identitymodel.RoleSchema{
			Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member",
		}); apperror.CodeOf(err) != "backend.identity.business_role_eligibility_required" {
			t.Fatalf("missing binding eligibility error=%v", err)
		}
	})

	t.Run("system-managed definition and binding shapes", func(t *testing.T) {
		valid := identitymodel.IdentityUserRoleAssignment{
			UserID: "user-1", RoleID: "member-id", BindingKey: "member", ProfileID: "profile",
		}
		cases := []struct {
			name       string
			definition identitymodel.RoleSchema
			assignment identitymodel.IdentityUserRoleAssignment
		}{
			{
				name: "manual mode",
				definition: identitymodel.RoleSchema{
					Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness,
					AssignmentMode: identitymodel.IdentityRoleAssignmentManual, RequiredBindingKey: "member",
				},
				assignment: valid,
			},
			{
				name: "non-business audience",
				definition: identitymodel.RoleSchema{
					Key: "member", Audience: identitymodel.IdentityRoleAudienceWorkforce,
					AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged, RequiredBindingKey: "member",
				},
				assignment: valid,
			},
			{
				name: "blank profile",
				definition: identitymodel.RoleSchema{
					Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness,
					AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged, RequiredBindingKey: "member",
				},
				assignment: identitymodel.IdentityUserRoleAssignment{
					UserID: "user-1", RoleID: "member-id", BindingKey: "member", ProfileID: " ",
				},
			},
			{
				name: "missing eligibility port",
				definition: identitymodel.RoleSchema{
					Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness,
					AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged, RequiredBindingKey: "member",
				},
				assignment: valid,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, service := identityRolesFixture()
				service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{tc.definition})
				if err := service.AssignSystemManagedRole(t.Context(), tc.assignment); apperror.CodeOf(err) != map[bool]string{
					true:  "backend.identity.business_role_eligibility_required",
					false: "backend.identity.system_managed_role_required",
				}[tc.definition.AssignmentMode == identitymodel.IdentityRoleAssignmentSystemManaged &&
					tc.definition.Audience == identitymodel.IdentityRoleAudienceBusiness] {
					t.Fatalf("system-managed shape error=%v", err)
				}
			})
		}
	})

	t.Run("governed removal missing and unpublished roles", func(t *testing.T) {
		repository, service := identityRolesFixture()
		if err := service.RemoveUserRole(t.Context(), "user-1", "missing-role"); err != nil || repository.removedUserRole != "missing-role" {
			t.Fatalf("missing role removal=%q err=%v", repository.removedUserRole, err)
		}
		repository.removedUserRole = ""
		service.ReplaceRoleDefinitions(nil)
		if err := service.RemoveUserRole(t.Context(), "user-1", "member-id"); err != nil || repository.removedUserRole != "member-id" {
			t.Fatalf("unpublished role removal=%q err=%v", repository.removedUserRole, err)
		}
	})

	t.Run("inactive bindings and non-manual roles are not assignable", func(t *testing.T) {
		repository, service := identityRolesFixture()
		repository.roles = []identitymodel.IdentityRole{
			{ID: "business-id", Key: "business", Label: "Business", Status: identitymodel.IdentityStatusActive},
			{ID: "system-id", Key: "system", Label: "System", Status: identitymodel.IdentityStatusActive},
			{ID: "request-id", Key: "request", Label: "Request", Status: identitymodel.IdentityStatusActive},
		}
		service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
			{Key: "business", Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
			{Key: "system", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged},
			{Key: "request", AssignmentMode: identitymodel.IdentityRoleAssignmentRequestOnly},
		})
		repository.profileBindings = []identitymodel.IdentityProfileBinding{{
			IdentityUserID: "user-1", BindingKey: "member", Status: identitymodel.IdentityProfileBindingSuspended,
		}}
		actor := identitymodel.Principal{
			Known: true, UserID: "admin", Role: identitymodel.RoleSchema{RecordScope: "all_records"},
		}
		roles, err := service.ListAssignableRoles(t.Context(), "user-1", actor)
		if err != nil || len(roles) != 0 {
			t.Fatalf("assignable roles=%v err=%v", roles, err)
		}
	})
}
