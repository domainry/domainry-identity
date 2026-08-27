package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type onboardingOnlyRepository struct {
	*identityScopedRepository
}

func (r *onboardingOnlyRepository) ApplyIdentityWorkforceOnboarding(context.Context, identitymodel.IdentityWorkforceOnboardingMutation) (identitymodel.IdentityWorkforceOnboardingResult, error) {
	return identitymodel.IdentityWorkforceOnboardingResult{}, nil
}

type onboardingWorkforceOnlyRepository struct {
	*identityScopedRepository
}

func (r *onboardingWorkforceOnlyRepository) ListIdentityWorkforceProfiles(context.Context, string) ([]identitymodel.IdentityWorkforceProfile, error) {
	return nil, nil
}
func (r *onboardingWorkforceOnlyRepository) GetIdentityWorkforceProfile(context.Context, string, string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	return identitymodel.IdentityWorkforceProfile{}, false, nil
}
func (r *onboardingWorkforceOnlyRepository) UpsertIdentityWorkforceProfile(context.Context, string, identitymodel.IdentityWorkforceProfile) error {
	return nil
}
func (r *onboardingWorkforceOnlyRepository) ListIdentityWorkforceAssignments(context.Context, string, string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	return nil, nil
}
func (r *onboardingWorkforceOnlyRepository) GetIdentityWorkforceAssignment(context.Context, string, string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	return identitymodel.IdentityWorkforceAssignment{}, false, nil
}
func (r *onboardingWorkforceOnlyRepository) UpsertIdentityWorkforceAssignment(context.Context, string, identitymodel.IdentityWorkforceAssignment) error {
	return nil
}

func onboardingApplicationFixture() (*IdentityApplicationService, *directoryProjectionRepository) {
	base := &identityScopedRepository{
		roles: []identitymodel.IdentityRole{{ID: "employee", Key: "employee", Label: "Employee"}},
	}
	repository := &directoryProjectionRepository{identityScopedRepository: base}
	return NewIdentityApplicationService(repository, nil), repository
}

func onboardingApplicationRequest() IdentityWorkforceOnboardingRequest {
	return IdentityWorkforceOnboardingRequest{
		User: identitymodel.IdentityUser{
			ID: " user-1 ", Name: " User One ", Email: " USER@EXAMPLE.TEST ", Status: identitymodel.IdentityStatusActive,
		},
		Profile: identitymodel.IdentityWorkforceProfile{
			ID: " workforce-1 ", OrganizationID: "org-1", WorkerNo: "E-1",
			WorkerType: identitymodel.IdentityWorkerEmployee, StartDate: "2026-07-25",
		},
		Assignment: identitymodel.IdentityWorkforceAssignment{
			ID: " assignment-1 ", OrganizationUnitID: "unit-1", EffectiveFrom: "2026-07-25",
		},
		RoleIDs: []string{"employee"}, Reason: " new hire ",
	}
}

func onboardingApplicationActor() identitymodel.Principal {
	return identitymodel.Principal{
		Known: true, UserID: "manager", WorkspaceID: "default",
		Role: identitymodel.RoleSchema{RecordScope: "all_records"},
	}
}

func TestOnboardWorkforceBuildsOneAtomicMutation(t *testing.T) {
	service, repository := onboardingApplicationFixture()
	result, err := service.OnboardWorkforce(
		requestcontext.WithWorkspaceID(t.Context(), "default"),
		onboardingApplicationRequest(),
		onboardingApplicationActor(),
	)
	if err != nil {
		t.Fatal(err)
	}
	mutation := repository.onboarded
	if result.User.ID != "user-1" || mutation.User.Email != "user@example.test" ||
		mutation.Profile.IdentityUserID != "user-1" || mutation.Profile.WorkStatus != identitymodel.IdentityWorkActive ||
		mutation.Profile.PrimaryAssignmentID != "assignment-1" ||
		mutation.Assignment.WorkforceProfileID != "workforce-1" ||
		mutation.Assignment.AssignmentType != identitymodel.IdentityWorkforceAssignmentPrimary ||
		mutation.Assignment.Status != identitymodel.IdentityStatusActive ||
		len(mutation.RoleAssignments) != 1 || mutation.RoleAssignments[0].WorkforceProfileID != "workforce-1" ||
		mutation.ActorID != "manager" || mutation.Reason != "new hire" {
		t.Fatalf("unexpected mutation: %#v", mutation)
	}
}

func TestOnboardWorkforceFailureBoundaries(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "default")
	request := onboardingApplicationRequest()
	actor := onboardingApplicationActor()
	service, repository := onboardingApplicationFixture()
	if _, err := service.OnboardWorkforce(t.Context(), request, actor); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("expected workspace error, got %v", err)
	}
	unavailable := NewIdentityApplicationService(&identityScopedRepository{}, nil)
	if _, err := unavailable.OnboardWorkforce(ctx, request, actor); apperror.CodeOf(err) != "backend.identity.workforce_onboarding_unavailable" {
		t.Fatalf("expected capability error, got %v", err)
	}
	for name, repository := range map[string]identityrepository.IdentityRepository{
		"onboarding only": &onboardingOnlyRepository{identityScopedRepository: &identityScopedRepository{}},
		"workforce only":  &onboardingWorkforceOnlyRepository{identityScopedRepository: &identityScopedRepository{}},
	} {
		if _, err := NewIdentityApplicationService(repository, nil).OnboardWorkforce(ctx, request, actor); apperror.CodeOf(err) != "backend.identity.workforce_onboarding_unavailable" {
			t.Fatalf("%s capability error=%v", name, err)
		}
	}
	repository.fail, repository.err = "users", errors.New("users")
	if _, err := service.OnboardWorkforce(ctx, request, actor); !errors.Is(err, repository.err) {
		t.Fatalf("expected user preparation error, got %v", err)
	}
	repository.fail = ""
	invalidProfile := request
	invalidProfile.Profile.OrganizationID = ""
	if _, err := service.OnboardWorkforce(ctx, invalidProfile, actor); apperror.CodeOf(err) != "backend.identity.workforce_profile_invalid" {
		t.Fatalf("expected profile error, got %v", err)
	}
	invalidAssignment := request
	invalidAssignment.Assignment.ID = ""
	if _, err := service.OnboardWorkforce(ctx, invalidAssignment, actor); apperror.CodeOf(err) != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("expected assignment error, got %v", err)
	}
	repository.fail, repository.err = "onboarding", errors.New("onboarding")
	if _, err := service.OnboardWorkforce(ctx, request, actor); !errors.Is(err, repository.err) {
		t.Fatalf("expected atomic store error, got %v", err)
	}
}
