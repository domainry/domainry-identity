package identity

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func memoryOnboardingMutation() identitymodel.IdentityWorkforceOnboardingMutation {
	return identitymodel.IdentityWorkforceOnboardingMutation{
		WorkspaceID: "workspace-primary",
		User:        identitymodel.IdentityUser{ID: "user", Name: "User"},
		Profile: identitymodel.IdentityWorkforceProfile{
			ID: "workforce", OrganizationID: "org", IdentityUserID: "user", WorkerNo: "E-1",
			WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
		},
		Assignment: identitymodel.IdentityWorkforceAssignment{
			ID: "assignment", WorkforceProfileID: "workforce", OrganizationUnitID: "unit",
			AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
		},
		RoleAssignments: []identitymodel.IdentityUserRoleAssignment{{
			UserID: "user", RoleID: "employee", WorkforceProfileID: "workforce", Source: "manual", Status: "active",
		}},
	}
}

func TestMemoryWorkforceOnboardingIsAtomicAndDefaultsVersions(t *testing.T) {
	store := NewMemoryIdentityStore()
	result, err := store.ApplyIdentityWorkforceOnboarding(t.Context(), memoryOnboardingMutation())
	if err != nil {
		t.Fatal(err)
	}
	if result.User.Status != identitymodel.IdentityStatusActive || result.Profile.Version != 1 || result.Assignment.Version != 1 {
		t.Fatalf("defaults not applied: %#v", result)
	}
	if len(store.users) != 1 || len(store.workforceProfiles) != 1 || len(store.workforceAssignments) != 1 || len(store.userRoles) != 1 {
		t.Fatalf("atomic graph missing: users=%d profiles=%d assignments=%d roles=%d", len(store.users), len(store.workforceProfiles), len(store.workforceAssignments), len(store.userRoles))
	}
	if _, err := store.ApplyIdentityWorkforceOnboarding(t.Context(), memoryOnboardingMutation()); err != nil {
		t.Fatalf("same aggregate replay failed: %v", err)
	}
}

func TestMemoryWorkforceOnboardingRejectsBeforeMutation(t *testing.T) {
	store := NewMemoryIdentityStore()
	for _, mutate := range []func(*identitymodel.IdentityWorkforceOnboardingMutation){
		func(value *identitymodel.IdentityWorkforceOnboardingMutation) { value.WorkspaceID = " " },
		func(value *identitymodel.IdentityWorkforceOnboardingMutation) { value.User.ID = "" },
		func(value *identitymodel.IdentityWorkforceOnboardingMutation) { value.Profile.ID = "" },
		func(value *identitymodel.IdentityWorkforceOnboardingMutation) { value.Assignment.ID = "" },
		func(value *identitymodel.IdentityWorkforceOnboardingMutation) {
			value.RoleAssignments[0].UserID = "other"
		},
		func(value *identitymodel.IdentityWorkforceOnboardingMutation) {
			value.RoleAssignments[0].WorkforceProfileID = "other"
		},
		func(value *identitymodel.IdentityWorkforceOnboardingMutation) { value.RoleAssignments[0].RoleID = "" },
	} {
		value := memoryOnboardingMutation()
		mutate(&value)
		if _, err := store.ApplyIdentityWorkforceOnboarding(t.Context(), value); err == nil {
			t.Fatalf("expected validation failure for %#v", value)
		}
		if len(store.users) != 0 || len(store.workforceProfiles) != 0 || len(store.workforceAssignments) != 0 || len(store.userRoles) != 0 {
			t.Fatal("invalid onboarding partially mutated memory state")
		}
	}
	existing := memoryOnboardingMutation()
	if _, err := store.ApplyIdentityWorkforceOnboarding(t.Context(), existing); err != nil {
		t.Fatal(err)
	}
	conflict := memoryOnboardingMutation()
	conflict.User.ID, conflict.User.Email = "other", "other@example.test"
	conflict.Profile.ID, conflict.Profile.IdentityUserID = "other-workforce", "other"
	conflict.Assignment.ID, conflict.Assignment.WorkforceProfileID = "other-assignment", "other-workforce"
	conflict.RoleAssignments = nil
	if _, err := store.ApplyIdentityWorkforceOnboarding(t.Context(), conflict); err == nil {
		t.Fatal("expected organization worker-number uniqueness conflict")
	}
	if len(store.users) != 1 || len(store.workforceProfiles) != 1 {
		t.Fatal("uniqueness conflict partially mutated memory state")
	}
}

func TestMemoryWorkforceOnboardingPreservesExplicitDefaultsAndChecksIdentityConflict(t *testing.T) {
	store := NewMemoryIdentityStore()
	first := memoryOnboardingMutation()
	first.User.Status = identitymodel.IdentityStatusDisabled
	first.Profile.Version = 4
	first.Assignment.Version = 5
	result, err := store.ApplyIdentityWorkforceOnboarding(t.Context(), first)
	if err != nil {
		t.Fatal(err)
	}
	if result.User.Status != identitymodel.IdentityStatusDisabled || result.Profile.Version != 4 || result.Assignment.Version != 5 {
		t.Fatalf("explicit values changed: %#v", result)
	}

	conflict := memoryOnboardingMutation()
	conflict.User.ID = "other-user"
	conflict.Profile.ID = "other-profile"
	conflict.Profile.WorkerNo = "E-2"
	conflict.Assignment.ID = "other-assignment"
	conflict.Assignment.WorkforceProfileID = conflict.Profile.ID
	conflict.RoleAssignments = nil
	if _, err := store.ApplyIdentityWorkforceOnboarding(t.Context(), conflict); err == nil {
		t.Fatal("expected identity-user uniqueness conflict")
	}

	otherOrganization := conflict
	otherOrganization.Profile.OrganizationID = "other-org"
	if _, err := store.ApplyIdentityWorkforceOnboarding(t.Context(), otherOrganization); err != nil {
		t.Fatalf("other organization should not conflict: %v", err)
	}
	unique := conflict
	unique.User.ID = "unique-user"
	unique.Profile.ID = "unique-profile"
	unique.Profile.IdentityUserID = unique.User.ID
	unique.Profile.WorkerNo = "E-3"
	unique.Assignment.ID = "unique-assignment"
	unique.Assignment.WorkforceProfileID = unique.Profile.ID
	if _, err := store.ApplyIdentityWorkforceOnboarding(t.Context(), unique); err != nil {
		t.Fatalf("unique same-organization profile should be accepted: %v", err)
	}
}
