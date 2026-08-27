package service

import (
	"context"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func TestIdentityUpsertUserWithRolesRejectsInvalidActorAndTargetScope(t *testing.T) {
	_, service := identityRolesFixture()
	user := validIdentityAtomicUser("user-1")

	if err := service.UpsertUserWithRoles(t.Context(), identitymodel.IdentityUser{}, nil, identitymodel.Principal{}); err == nil {
		t.Fatal("invalid user was accepted")
	}
	for _, actor := range []identitymodel.Principal{
		{},
		{Known: true, UserID: " "},
	} {
		if err := service.UpsertUserWithRoles(t.Context(), user, nil, actor); apperror.CodeOf(err) != "backend.identity.entitlement_actor_required" {
			t.Fatalf("actor=%+v error=%v", actor, err)
		}
	}
	if err := service.UpsertUserWithRoles(t.Context(), user, nil, identitymodel.Principal{
		Known: true, UserID: "other", Role: identitymodel.RoleSchema{RecordScope: "none"},
	}); apperror.CodeOf(err) != "backend.identity.role_target_scope_denied" {
		t.Fatalf("target scope error=%v", err)
	}
}

func TestIdentityUpsertUserWithRolesPropagatesWorkforceAndAssignmentValidationErrors(t *testing.T) {
	repository, service := identityRolesFixture()
	user := validIdentityAtomicUser("user-1")
	actor := identitymodel.Principal{Known: true, UserID: "admin", Role: identitymodel.RoleSchema{RecordScope: "all_records"}}

	repository.workforceErr = errIdentityRolesRepository
	if err := service.UpsertUserWithRoles(t.Context(), user, nil, actor); err != errIdentityRolesRepository {
		t.Fatalf("workforce error=%v", err)
	}
	repository.workforceErr = nil
	repository.getUserErr = errIdentityRolesRepository
	if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id"}}, actor); err != errIdentityRolesRepository {
		t.Fatalf("assignment validation error=%v", err)
	}
	repository.getUserErr = nil
	invalidExpiry := "not-a-time"
	if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{
		RoleID: "member-id", ExpiresAt: &invalidExpiry,
	}}, actor); apperror.CodeOf(err) != "backend.identity.assignment_expires_at_invalid" {
		t.Fatalf("configuration error=%v", err)
	}
}

func TestIdentityUpsertUserWithRolesNormalizesDeduplicatesAndFiltersNewUserIssue(t *testing.T) {
	repository, service := identityRolesFixture()
	actor := identitymodel.Principal{Known: true, UserID: "admin", Role: identitymodel.RoleSchema{RecordScope: "all_records"}}
	user := validIdentityAtomicUser("new-user")
	assignments := []identitymodel.IdentityUserRoleAssignment{
		{RoleID: " member-id "},
		{RoleID: "member-id"},
	}
	if err := service.UpsertUserWithRoles(t.Context(), user, assignments, actor); err != nil {
		t.Fatal(err)
	}
	if len(repository.reconciledRoles) != 1 || repository.reconciledRoles[0].RoleID != "member-id" {
		t.Fatalf("reconciled roles=%+v", repository.reconciledRoles)
	}
	if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: " "}}, actor); apperror.CodeOf(err) != "backend.identity.role_required" {
		t.Fatalf("empty role error=%v", err)
	}
}

func TestIdentityUpsertUserWithRolesHandlesRoleLookupPublicationAndEligibilityEdges(t *testing.T) {
	user := validIdentityAtomicUser("user-1")
	actor := identitymodel.Principal{Known: true, UserID: "admin", Role: identitymodel.RoleSchema{RecordScope: "all_records"}}

	t.Run("role disappears after validation", func(t *testing.T) {
		repository, service := identityRolesFixture()
		repository.listRolesFunc = func(call int) ([]identitymodel.IdentityRole, error) {
			if call == 1 {
				return append([]identitymodel.IdentityRole(nil), repository.roles...), nil
			}
			return nil, nil
		}
		if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id"}}, actor); apperror.CodeOf(err) != "backend.identity.role_not_found" {
			t.Fatalf("role not found error=%v", err)
		}
	})

	t.Run("second role lookup fails", func(t *testing.T) {
		repository, service := identityRolesFixture()
		repository.listRolesFunc = func(call int) ([]identitymodel.IdentityRole, error) {
			if call == 1 {
				return append([]identitymodel.IdentityRole(nil), repository.roles...), nil
			}
			return nil, errIdentityRolesRepository
		}
		if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id"}}, actor); err != errIdentityRolesRepository {
			t.Fatalf("role lookup error=%v", err)
		}
	})

	t.Run("unpublished role uses safe defaults", func(t *testing.T) {
		repository, service := identityRolesFixture()
		service.ReplaceRoleDefinitions(nil)
		if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id"}}, actor); err != nil {
			t.Fatal(err)
		}
		if len(repository.reconciledRoles) != 1 {
			t.Fatalf("reconciled roles=%+v", repository.reconciledRoles)
		}
	})

	t.Run("published eligibility is enforced", func(t *testing.T) {
		_, service := identityRolesFixture()
		service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
			Key: "member", Audience: identitymodel.IdentityRoleAudienceWorkforce,
			AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
		}})
		if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id"}}, actor); apperror.CodeOf(err) != "backend.identity.workforce_role_eligibility_required" {
			t.Fatalf("eligibility error=%v", err)
		}
	})
}

func TestIdentityUpsertUserWithRolesEnforcesRiskCeilingAndPairConflicts(t *testing.T) {
	user := validIdentityAtomicUser("user-1")
	allRecords := identitymodel.RoleSchema{RecordScope: "all_records"}

	t.Run("privileged self grant", func(t *testing.T) {
		repository, service := identityRolesFixture()
		service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
			Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
			RiskLevel: identitymodel.IdentityRoleRiskPrivileged,
		}})
		actor := identitymodel.Principal{Known: true, UserID: "user-1", Role: identitymodel.RoleSchema{
			RecordScope: "all_records", GrantableRoleKeys: []string{"*"},
		}}
		if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id"}}, actor); apperror.CodeOf(err) != "backend.identity.privileged_self_grant_denied" {
			t.Fatalf("self grant error=%v", err)
		}
		actor.UserID = "admin"
		if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id"}}, actor); err != nil {
			t.Fatalf("privileged grant by another principal error=%v", err)
		}
		if len(repository.reconciledRoles) != 1 {
			t.Fatalf("reconciled roles=%+v", repository.reconciledRoles)
		}
	})

	t.Run("elevated grant ceiling", func(t *testing.T) {
		_, service := identityRolesFixture()
		service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
			Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
			RiskLevel: identitymodel.IdentityRoleRiskElevated,
		}})
		actor := identitymodel.Principal{Known: true, UserID: "admin", Role: allRecords}
		if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id"}}, actor); apperror.CodeOf(err) != "backend.identity.role_grant_ceiling_exceeded" {
			t.Fatalf("grant ceiling error=%v", err)
		}
		actor.Role.GrantableRoleKeys = []string{"member"}
		if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id"}}, actor); err != nil {
			t.Fatalf("specific grant ceiling error=%v", err)
		}
		actor.Role.GrantableRoleKeys = []string{"*"}
		if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id"}}, actor); err != nil {
			t.Fatalf("wildcard grant ceiling error=%v", err)
		}
	})

	for _, conflictOnLeft := range []bool{true, false} {
		name := "right definition declares conflict"
		if conflictOnLeft {
			name = "left definition declares conflict"
		}
		t.Run(name, func(t *testing.T) {
			_, service := identityRolesFixture()
			member := identitymodel.RoleSchema{Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual}
			viewer := identitymodel.RoleSchema{Key: "viewer", AssignmentMode: identitymodel.IdentityRoleAssignmentManual}
			if conflictOnLeft {
				member.ConflictRoleKeys = []string{"viewer"}
			} else {
				viewer.ConflictRoleKeys = []string{"member"}
			}
			service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{member, viewer})
			actor := identitymodel.Principal{Known: true, UserID: "admin", Role: allRecords}
			if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{
				{RoleID: "member-id"}, {RoleID: "viewer-id"},
			}, actor); apperror.CodeOf(err) != "backend.identity.role_conflict" {
				t.Fatalf("conflict error=%v", err)
			}
		})
	}

	t.Run("non-conflicting pair", func(t *testing.T) {
		repository, service := identityRolesFixture()
		service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
			{Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
			{Key: "viewer", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		})
		actor := identitymodel.Principal{Known: true, UserID: "admin", Role: allRecords}
		if err := service.UpsertUserWithRoles(t.Context(), user, []identitymodel.IdentityUserRoleAssignment{
			{RoleID: "member-id"}, {RoleID: "viewer-id"},
		}, actor); err != nil {
			t.Fatal(err)
		}
		if len(repository.reconciledRoles) != 2 {
			t.Fatalf("reconciled roles=%+v", repository.reconciledRoles)
		}
	})
}

type identityNonAtomicRepository struct {
	identityrepository.IdentityRepository
}

func validIdentityAtomicUser(id string) identitymodel.IdentityUser {
	return identitymodel.IdentityUser{
		ID: id, Name: "Identity User", Email: id + "@example.com",
		Status: identitymodel.IdentityStatusActive,
	}
}

func TestIdentityUpsertUserWithRolesRequiresAtomicRepository(t *testing.T) {
	repository, _ := identityRolesFixture()
	service, err := NewIdentityDomainService(identityNonAtomicRepository{IdentityRepository: repository}, nil).ForWorkspace("workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual}})
	err = service.UpsertUserWithRoles(
		context.Background(),
		validIdentityAtomicUser("user-1"),
		nil,
		identitymodel.Principal{Known: true, UserID: "admin", Role: identitymodel.RoleSchema{RecordScope: "all_records"}},
	)
	if apperror.CodeOf(err) != "backend.internal" {
		t.Fatalf("atomic repository error=%v", err)
	}
}
