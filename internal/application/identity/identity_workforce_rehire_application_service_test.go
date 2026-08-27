package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type rehireWorkforceRepository struct {
	*identityScopedRepository
	profile            identitymodel.IdentityWorkforceProfile
	found              bool
	assignments        []identitymodel.IdentityWorkforceAssignment
	assignment         identitymodel.IdentityWorkforceAssignment
	assignmentFound    bool
	assignmentErr      error
	loadErr            error
	listErr            error
	applyErr           error
	terminationErr     error
	getUserErr         error
	bindingsErr        error
	bindings           []identitymodel.IdentityProfileBinding
	transferReceipts   map[string]identitymodel.IdentityWorkforceTransferBatchReceipt
	transferReceiptErr error
	transferApplyErr   error
	transferApplied    identitymodel.IdentityWorkforceTransferBatchMutation
	applied            identitymodel.IdentityWorkforceLifecycleMutation
	terminated         identitymodel.IdentityWorkforceTerminationMutation
}

func (r *rehireWorkforceRepository) ListIdentityWorkforceProfiles(context.Context, string) ([]identitymodel.IdentityWorkforceProfile, error) {
	return []identitymodel.IdentityWorkforceProfile{r.profile}, nil
}

func (r *rehireWorkforceRepository) GetIdentityWorkforceProfile(context.Context, string, string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	return r.profile, r.found, r.loadErr
}

func (r *rehireWorkforceRepository) UpsertIdentityWorkforceProfile(context.Context, string, identitymodel.IdentityWorkforceProfile) error {
	return nil
}

func (r *rehireWorkforceRepository) ListIdentityWorkforceAssignments(context.Context, string, string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	return r.assignments, r.listErr
}

func (r *rehireWorkforceRepository) GetIdentityWorkforceAssignment(context.Context, string, string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	return r.assignment, r.assignmentFound, r.assignmentErr
}

func (r *rehireWorkforceRepository) UpsertIdentityWorkforceAssignment(context.Context, string, identitymodel.IdentityWorkforceAssignment) error {
	return nil
}

func (r *rehireWorkforceRepository) ApplyIdentityWorkforceLifecycle(_ context.Context, mutation identitymodel.IdentityWorkforceLifecycleMutation) (identitymodel.IdentityWorkforceLifecycleResult, error) {
	r.applied = mutation
	if r.applyErr != nil {
		return identitymodel.IdentityWorkforceLifecycleResult{}, r.applyErr
	}
	return identitymodel.IdentityWorkforceLifecycleResult{Profile: mutation.Profile, Assignments: mutation.UpsertAssignments}, nil
}

func (r *rehireWorkforceRepository) TerminateIdentityWorkforce(_ context.Context, mutation identitymodel.IdentityWorkforceTerminationMutation) (identitymodel.IdentityWorkforceTerminationResult, error) {
	r.terminated = mutation
	if r.terminationErr != nil {
		return identitymodel.IdentityWorkforceTerminationResult{}, r.terminationErr
	}
	return identitymodel.IdentityWorkforceTerminationResult{Profile: mutation.Profile}, nil
}

func (r *rehireWorkforceRepository) GetIdentityUser(ctx context.Context, workspaceID, userID string) (identitymodel.IdentityUser, bool, error) {
	if r.getUserErr != nil {
		return identitymodel.IdentityUser{}, false, r.getUserErr
	}
	return r.identityScopedRepository.GetIdentityUser(ctx, workspaceID, userID)
}

func (r *rehireWorkforceRepository) ListIdentityProfileBindingsByUser(context.Context, string, string) ([]identitymodel.IdentityProfileBinding, error) {
	return r.bindings, r.bindingsErr
}

func (r *rehireWorkforceRepository) GetIdentityWorkforceTransferBatchReceipt(_ context.Context, _, idempotencyKey string) (identitymodel.IdentityWorkforceTransferBatchReceipt, bool, error) {
	if r.transferReceiptErr != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, false, r.transferReceiptErr
	}
	receipt, found := r.transferReceipts[idempotencyKey]
	return receipt, found, nil
}

func (r *rehireWorkforceRepository) ApplyIdentityWorkforceTransferBatch(_ context.Context, mutation identitymodel.IdentityWorkforceTransferBatchMutation) (identitymodel.IdentityWorkforceTransferBatchReceipt, error) {
	r.transferApplied = mutation
	if r.transferApplyErr != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, r.transferApplyErr
	}
	if r.transferReceipts == nil {
		r.transferReceipts = map[string]identitymodel.IdentityWorkforceTransferBatchReceipt{}
	}
	receipt := identitymodel.IdentityWorkforceTransferBatchReceipt{
		ID: "receipt", WorkspaceID: mutation.WorkspaceID, ActorID: mutation.ActorID,
		IdempotencyKey: mutation.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint, Items: mutation.Items,
	}
	r.transferReceipts[mutation.IdempotencyKey] = receipt
	return receipt, nil
}

func rehireApplicationFixture() (*IdentityApplicationService, *rehireWorkforceRepository) {
	repository := &rehireWorkforceRepository{
		identityScopedRepository: &identityScopedRepository{},
		found:                    true,
		profile: identitymodel.IdentityWorkforceProfile{
			ID: "workforce-1", OrganizationID: "org-1", IdentityUserID: "user-1", WorkerNo: "E-1",
			WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkTerminated,
			StartDate: "2025-01-01", EndDate: "2026-01-01", PrimaryAssignmentID: "old-primary",
		},
		assignments: []identitymodel.IdentityWorkforceAssignment{{
			ID: "old-primary", WorkforceProfileID: "workforce-1", OrganizationUnitID: "unit-old",
			AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusDisabled,
			EffectiveFrom: "2025-01-01", EffectiveTo: "2026-01-01",
		}},
	}
	return NewIdentityApplicationService(repository, nil), repository
}

func TestRehireWorkforceCreatesFreshAssignmentWithoutEntitlementMutation(t *testing.T) {
	service, repository := rehireApplicationFixture()
	result, err := service.RehireWorkforce(
		requestcontext.WithWorkspaceID(t.Context(), "default"), " workforce-1 ", "2026-08-01",
		identitymodel.IdentityWorkforceAssignment{ID: "new-primary", OrganizationUnitID: "unit-new"},
		identitymodel.Principal{UserID: "admin"}, " rehired ",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile == nil || result.Profile.WorkStatus != identitymodel.IdentityWorkActive ||
		result.Profile.PrimaryAssignmentID != "new-primary" || result.Profile.EndDate != "" ||
		len(result.Assignments) != 1 || result.Assignments[0].ID != "new-primary" ||
		result.Assignments[0].AssignmentType != identitymodel.IdentityWorkforceAssignmentPrimary ||
		result.Assignments[0].Status != identitymodel.IdentityStatusActive ||
		repository.applied.RevokeEntitlements || repository.applied.ActorID != "admin" ||
		repository.applied.Reason != "rehired" {
		t.Fatalf("result=%+v mutation=%+v", result, repository.applied)
	}
}

func TestRehireWorkforceRejectsEveryInvalidBoundary(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "default")
	assignment := identitymodel.IdentityWorkforceAssignment{ID: "new-primary", OrganizationUnitID: "unit-new"}
	service, repository := rehireApplicationFixture()
	if _, err := service.RehireWorkforce(t.Context(), "workforce-1", "2026-08-01", assignment, identitymodel.Principal{}, "rehired"); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("workspace err=%v", err)
	}
	unavailable := NewIdentityApplicationService(&identityScopedRepository{}, nil)
	if _, err := unavailable.RehireWorkforce(ctx, "workforce-1", "2026-08-01", assignment, identitymodel.Principal{}, "rehired"); apperror.CodeOf(err) != "backend.identity.workforce_lifecycle_unavailable" {
		t.Fatalf("capability err=%v", err)
	}
	workforceOnly := NewIdentityApplicationService(&onboardingWorkforceOnlyRepository{identityScopedRepository: &identityScopedRepository{}}, nil)
	if _, err := workforceOnly.RehireWorkforce(ctx, "workforce-1", "2026-08-01", assignment, identitymodel.Principal{}, "rehired"); apperror.CodeOf(err) != "backend.identity.workforce_lifecycle_unavailable" {
		t.Fatalf("missing lifecycle capability err=%v", err)
	}
	if _, err := service.RehireWorkforce(ctx, "workforce-1", "bad-date", assignment, identitymodel.Principal{}, "rehired"); apperror.CodeOf(err) != "backend.identity.workforce_lifecycle_effective_date_invalid" {
		t.Fatalf("date err=%v", err)
	}
	repository.loadErr = errors.New("load")
	if _, err := service.RehireWorkforce(ctx, "workforce-1", "2026-08-01", assignment, identitymodel.Principal{}, "rehired"); !errors.Is(err, repository.loadErr) {
		t.Fatalf("load err=%v", err)
	}
	repository.loadErr, repository.found = nil, false
	if _, err := service.RehireWorkforce(ctx, "workforce-1", "2026-08-01", assignment, identitymodel.Principal{}, "rehired"); apperror.CodeOf(err) != "backend.identity.workforce_profile_not_found" {
		t.Fatalf("not found err=%v", err)
	}
	repository.found, repository.profile.WorkStatus = true, identitymodel.IdentityWorkActive
	if _, err := service.RehireWorkforce(ctx, "workforce-1", "2026-08-01", assignment, identitymodel.Principal{}, "rehired"); apperror.CodeOf(err) != "backend.identity.workforce_rehire_requires_terminated" {
		t.Fatalf("status err=%v", err)
	}
	repository.profile.WorkStatus = identitymodel.IdentityWorkTerminated
	invalid := assignment
	invalid.ID = ""
	if _, err := service.RehireWorkforce(ctx, "workforce-1", "2026-08-01", invalid, identitymodel.Principal{}, "rehired"); apperror.CodeOf(err) != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("assignment err=%v", err)
	}
	repository.listErr = errors.New("list")
	if _, err := service.RehireWorkforce(ctx, "workforce-1", "2026-08-01", assignment, identitymodel.Principal{}, "rehired"); apperror.CodeOf(err) != "backend.internal" {
		t.Fatalf("assignment list err=%v", err)
	}
	repository.listErr, repository.applyErr = nil, errors.New("apply")
	if _, err := service.RehireWorkforce(ctx, "workforce-1", "2026-08-01", assignment, identitymodel.Principal{}, "rehired"); !errors.Is(err, repository.applyErr) {
		t.Fatalf("apply err=%v", err)
	}
}

func lifecycleApplicationRequest(operation string) IdentityWorkforceLifecycleRequest {
	return IdentityWorkforceLifecycleRequest{
		Operation: operation,
		Profile: identitymodel.IdentityWorkforceProfile{
			ID: "workforce-1", OrganizationID: "org-1", IdentityUserID: "user-1", WorkerNo: "E-1",
			WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
			StartDate: "2025-01-01", PrimaryAssignmentID: "old-primary",
		},
		Assignment: identitymodel.IdentityWorkforceAssignment{
			ID: "new-assignment", OrganizationUnitID: "unit-new", EffectiveFrom: "2026-08-01",
		},
		PreviousAssignmentID: "old-primary", EffectiveAt: "2026-08-01", ActorID: " admin ", Reason: " change ",
	}
}

func lifecycleApplicationFixture() (*IdentityApplicationService, *rehireWorkforceRepository) {
	service, repository := rehireApplicationFixture()
	repository.identityScopedRepository.users = []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}}
	repository.profile.WorkStatus = identitymodel.IdentityWorkActive
	repository.profile.EndDate = ""
	repository.assignment = identitymodel.IdentityWorkforceAssignment{
		ID: "old-primary", WorkforceProfileID: "workforce-1", OrganizationUnitID: "unit-old",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
		EffectiveFrom: "2025-01-01",
	}
	repository.assignmentFound = true
	repository.assignments = []identitymodel.IdentityWorkforceAssignment{
		repository.assignment,
		{ID: "inactive", WorkforceProfileID: "workforce-1", AssignmentType: identitymodel.IdentityWorkforceAssignmentSecondary, Status: identitymodel.IdentityStatusDisabled},
	}
	return service, repository
}

func TestApplyWorkforceLifecycleSupportsEveryOperation(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "default")
	operations := []string{
		IdentityWorkforceLifecycleInvite,
		IdentityWorkforceLifecycleOnboard,
		IdentityWorkforceLifecycleAssign,
		IdentityWorkforceLifecycleAddSecondary,
		IdentityWorkforceLifecycleTransfer,
		IdentityWorkforceLifecycleSuspend,
		IdentityWorkforceLifecycleRevokeAccess,
	}
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			service, repository := lifecycleApplicationFixture()
			request := lifecycleApplicationRequest(operation)
			if operation == IdentityWorkforceLifecycleAssign {
				request.Assignment.AssignmentType = ""
			}
			if operation == IdentityWorkforceLifecycleOnboard {
				request.Profile.PrimaryAssignmentID = ""
				repository.assignments = nil
			}
			result, err := service.ApplyWorkforceLifecycle(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if operation == IdentityWorkforceLifecycleInvite && (result.Profile == nil || result.Profile.WorkStatus != identitymodel.IdentityWorkPending) {
				t.Fatalf("invite result=%#v", result)
			}
			if operation == IdentityWorkforceLifecycleAssign && repository.applied.UpsertAssignments[0].AssignmentType != identitymodel.IdentityWorkforceAssignmentTemporary {
				t.Fatalf("assign mutation=%#v", repository.applied)
			}
			if operation == IdentityWorkforceLifecycleAddSecondary && repository.applied.UpsertAssignments[0].AssignmentType != identitymodel.IdentityWorkforceAssignmentSecondary {
				t.Fatalf("secondary mutation=%#v", repository.applied)
			}
			if operation == IdentityWorkforceLifecycleTransfer && (len(repository.applied.EndAssignments) != 1 || repository.applied.Profile.PrimaryAssignmentID != "new-assignment") {
				t.Fatalf("transfer mutation=%#v", repository.applied)
			}
			if operation == IdentityWorkforceLifecycleSuspend && (len(repository.applied.EndAssignments) != 1 || !repository.applied.RevokeEntitlements) {
				t.Fatalf("suspend mutation=%#v", repository.applied)
			}
			if operation == IdentityWorkforceLifecycleRevokeAccess && !repository.applied.RevokeEntitlements {
				t.Fatalf("revoke mutation=%#v", repository.applied)
			}
		})
	}
}

func TestApplyWorkforceLifecycleRejectsEveryBoundary(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "default")
	service, repository := lifecycleApplicationFixture()
	validAssign := lifecycleApplicationRequest(IdentityWorkforceLifecycleAssign)
	if _, err := service.ApplyWorkforceLifecycle(t.Context(), validAssign); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("workspace error=%v", err)
	}
	unavailable := NewIdentityApplicationService(&identityScopedRepository{}, nil)
	if _, err := unavailable.ApplyWorkforceLifecycle(ctx, validAssign); apperror.CodeOf(err) != "backend.identity.workforce_lifecycle_unavailable" {
		t.Fatalf("unavailable error=%v", err)
	}
	workforceOnly := NewIdentityApplicationService(&onboardingWorkforceOnlyRepository{identityScopedRepository: &identityScopedRepository{}}, nil)
	if _, err := workforceOnly.ApplyWorkforceLifecycle(ctx, validAssign); apperror.CodeOf(err) != "backend.identity.workforce_lifecycle_unavailable" {
		t.Fatalf("missing lifecycle capability error=%v", err)
	}
	unknown := lifecycleApplicationRequest("unknown")
	if _, err := service.ApplyWorkforceLifecycle(ctx, unknown); apperror.CodeOf(err) != "backend.identity.workforce_lifecycle_operation_invalid" {
		t.Fatalf("unknown operation=%v", err)
	}
	for _, operation := range []string{IdentityWorkforceLifecycleInvite, IdentityWorkforceLifecycleOnboard} {
		request := lifecycleApplicationRequest(operation)
		request.Profile.OrganizationID = ""
		if _, err := service.ApplyWorkforceLifecycle(ctx, request); apperror.CodeOf(err) != "backend.identity.workforce_profile_invalid" {
			t.Fatalf("%s profile error=%v", operation, err)
		}
	}
	invalidOnboard := lifecycleApplicationRequest(IdentityWorkforceLifecycleOnboard)
	invalidOnboard.Profile.PrimaryAssignmentID = ""
	invalidOnboard.Assignment.ID = ""
	if _, err := service.ApplyWorkforceLifecycle(ctx, invalidOnboard); apperror.CodeOf(err) != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("onboard assignment error=%v", err)
	}

	for _, operation := range []string{
		IdentityWorkforceLifecycleAssign, IdentityWorkforceLifecycleTransfer,
		IdentityWorkforceLifecycleSuspend, IdentityWorkforceLifecycleRevokeAccess,
	} {
		repository.loadErr = errors.New("load " + operation)
		request := lifecycleApplicationRequest(operation)
		if _, err := service.ApplyWorkforceLifecycle(ctx, request); !errors.Is(err, repository.loadErr) {
			t.Fatalf("%s load error=%v", operation, err)
		}
		repository.loadErr, repository.found = nil, false
		if _, err := service.ApplyWorkforceLifecycle(ctx, request); apperror.CodeOf(err) != "backend.identity.workforce_profile_not_found" {
			t.Fatalf("%s missing profile=%v", operation, err)
		}
		repository.found = true
	}
	for _, operation := range []string{IdentityWorkforceLifecycleTransfer, IdentityWorkforceLifecycleSuspend} {
		request := lifecycleApplicationRequest(operation)
		request.EffectiveAt = "bad"
		if _, err := service.ApplyWorkforceLifecycle(ctx, request); apperror.CodeOf(err) != "backend.identity.workforce_lifecycle_effective_date_invalid" {
			t.Fatalf("%s date error=%v", operation, err)
		}
	}
	invalidAssign := lifecycleApplicationRequest(IdentityWorkforceLifecycleAssign)
	invalidAssign.Assignment.ID = ""
	if _, err := service.ApplyWorkforceLifecycle(ctx, invalidAssign); apperror.CodeOf(err) != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("assign validation=%v", err)
	}
	explicitAssign := lifecycleApplicationRequest(IdentityWorkforceLifecycleAssign)
	explicitAssign.Assignment.AssignmentType = identitymodel.IdentityWorkforceAssignmentSecondary
	if _, err := service.ApplyWorkforceLifecycle(ctx, explicitAssign); err != nil {
		t.Fatalf("explicit assignment type=%v", err)
	}

	transfer := lifecycleApplicationRequest(IdentityWorkforceLifecycleTransfer)
	repository.assignmentErr = errors.New("previous")
	if _, err := service.ApplyWorkforceLifecycle(ctx, transfer); !errors.Is(err, repository.assignmentErr) {
		t.Fatalf("previous error=%v", err)
	}
	repository.assignmentErr, repository.assignmentFound = nil, false
	if _, err := service.ApplyWorkforceLifecycle(ctx, transfer); apperror.CodeOf(err) != "backend.identity.workforce_transfer_source_invalid" {
		t.Fatalf("missing previous=%v", err)
	}
	repository.assignmentFound = true
	for name, mutate := range map[string]func(*identitymodel.IdentityWorkforceAssignment){
		"profile": func(a *identitymodel.IdentityWorkforceAssignment) { a.WorkforceProfileID = "other" },
		"type": func(a *identitymodel.IdentityWorkforceAssignment) {
			a.AssignmentType = identitymodel.IdentityWorkforceAssignmentSecondary
		},
		"status": func(a *identitymodel.IdentityWorkforceAssignment) { a.Status = identitymodel.IdentityStatusDisabled },
	} {
		original := repository.assignment
		mutate(&repository.assignment)
		if _, err := service.ApplyWorkforceLifecycle(ctx, transfer); apperror.CodeOf(err) != "backend.identity.workforce_transfer_source_invalid" {
			t.Fatalf("%s previous=%v", name, err)
		}
		repository.assignment = original
	}
	invalidTransfer := transfer
	invalidTransfer.Assignment.ID = ""
	if _, err := service.ApplyWorkforceLifecycle(ctx, invalidTransfer); apperror.CodeOf(err) != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("transfer assignment=%v", err)
	}

	repository.listErr = errors.New("list")
	if _, err := service.ApplyWorkforceLifecycle(ctx, lifecycleApplicationRequest(IdentityWorkforceLifecycleSuspend)); !errors.Is(err, repository.listErr) {
		t.Fatalf("suspend list error=%v", err)
	}
	repository.listErr = nil
	originalProfile := repository.profile
	repository.profile.IdentityUserID = ""
	if _, err := service.ApplyWorkforceLifecycle(ctx, lifecycleApplicationRequest(IdentityWorkforceLifecycleSuspend)); apperror.CodeOf(err) != "backend.identity.workforce_profile_invalid" {
		t.Fatalf("suspend profile validation=%v", err)
	}
	repository.profile = originalProfile
	repository.applyErr = errors.New("apply")
	if _, err := service.ApplyWorkforceLifecycle(ctx, lifecycleApplicationRequest(IdentityWorkforceLifecycleRevokeAccess)); !errors.Is(err, repository.applyErr) {
		t.Fatalf("apply error=%v", err)
	}
}

func TestIdentityApplicationWorkforceDirectoryValidationAndTermination(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "default")
	service, repository := lifecycleApplicationFixture()
	repository.bindings = []identitymodel.IdentityProfileBinding{
		{BindingKey: "active", Status: identitymodel.IdentityProfileBindingActive},
		{BindingKey: "old", Status: identitymodel.IdentityProfileBindingUnlinked},
	}
	profile := repository.profile
	assignment := identitymodel.IdentityWorkforceAssignment{
		ID: "secondary", WorkforceProfileID: profile.ID, OrganizationUnitID: "unit-two",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentSecondary, Status: identitymodel.IdentityStatusActive,
		EffectiveFrom: "2026-01-01",
	}
	if profiles, err := service.ListWorkforceProfiles(ctx); err != nil || len(profiles) != 1 {
		t.Fatalf("profiles=%#v err=%v", profiles, err)
	}
	if page, err := service.SearchWorkforceProfiles(ctx, identitymodelWorkforceQuery()); err != nil || page.Total != 1 {
		t.Fatalf("search=%#v err=%v", page, err)
	}
	if loaded, found, err := service.GetWorkforceProfile(ctx, "workforce-1"); err != nil || !found || loaded.ID != profile.ID {
		t.Fatalf("profile=%#v found=%v err=%v", loaded, found, err)
	}
	if detail, found, err := service.GetWorkforceDetail(ctx, "workforce-1"); err != nil || !found ||
		detail.Account.ID != "user-1" || len(detail.BusinessProfiles) != 1 {
		t.Fatalf("detail=%#v found=%v err=%v", detail, found, err)
	}
	if err := service.ValidateWorkforceProfile(ctx, profile); err != nil {
		t.Fatalf("validate profile=%v", err)
	}
	if err := service.UpsertWorkforceProfile(ctx, profile); err != nil {
		t.Fatalf("upsert profile=%v", err)
	}
	if assignments, err := service.ListWorkforceAssignments(ctx, profile.ID); err != nil || len(assignments) != 2 {
		t.Fatalf("assignments=%#v err=%v", assignments, err)
	}
	if err := service.ValidateWorkforceAssignment(ctx, assignment); err != nil {
		t.Fatalf("validate assignment=%v", err)
	}
	if err := service.UpsertWorkforceAssignment(ctx, assignment); err != nil {
		t.Fatalf("upsert assignment=%v", err)
	}
	terminated, err := service.TerminateWorkforceProfile(ctx, profile.ID, "2026-08-01", identitymodel.IdentityWorkforceTerminationOptions{
		ActorID: " admin ", Reason: " leaving ",
	})
	if err != nil || terminated.WorkStatus != identitymodel.IdentityWorkTerminated ||
		repository.terminated.ActorID != "admin" || repository.terminated.Reason != "leaving" {
		t.Fatalf("terminated=%#v mutation=%#v err=%v", terminated, repository.terminated, err)
	}
	if _, err := service.TerminateWorkforceProfile(ctx, profile.ID, "2026-08-01"); err != nil {
		t.Fatalf("termination without options=%v", err)
	}
}

func identitymodelWorkforceQuery() identitymodel.IdentityListQuery {
	return identitymodel.IdentityListQuery{}
}

func TestIdentityApplicationWorkforceFailureBoundaries(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "default")
	service, repository := lifecycleApplicationFixture()
	profile := repository.profile
	assignment := identitymodel.IdentityWorkforceAssignment{
		ID: "secondary", WorkforceProfileID: profile.ID, OrganizationUnitID: "unit-two",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentSecondary, Status: identitymodel.IdentityStatusActive,
		EffectiveFrom: "2026-01-01",
	}
	missingScope := []func() error{
		func() error { _, err := service.ListWorkforceProfiles(t.Context()); return err },
		func() error {
			_, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{})
			return err
		},
		func() error { _, _, err := service.GetWorkforceProfile(t.Context(), profile.ID); return err },
		func() error { _, _, err := service.GetWorkforceDetail(t.Context(), profile.ID); return err },
		func() error { return service.UpsertWorkforceProfile(t.Context(), profile) },
		func() error { return service.ValidateWorkforceProfile(t.Context(), profile) },
		func() error {
			_, err := service.TerminateWorkforceProfile(t.Context(), profile.ID, "2026-08-01")
			return err
		},
		func() error { _, err := service.ListWorkforceAssignments(t.Context(), profile.ID); return err },
		func() error { return service.UpsertWorkforceAssignment(t.Context(), assignment) },
		func() error { return service.ValidateWorkforceAssignment(t.Context(), assignment) },
	}
	for index, call := range missingScope {
		if err := call(); apperror.CodeOf(err) != "backend.workspace_scope_required" {
			t.Fatalf("missing scope %d=%v", index, err)
		}
	}

	plainScoped, err := NewIdentityApplicationService(&identityScopedRepository{}, nil).ForWorkspace("default")
	if err != nil {
		t.Fatal(err)
	}
	for index, call := range []func() error{
		func() error { _, err := plainScoped.ListWorkforceProfiles(ctx); return err },
		func() error { _, _, err := plainScoped.GetWorkforceProfile(ctx, profile.ID); return err },
		func() error { return plainScoped.UpsertWorkforceProfile(ctx, profile) },
		func() error { return plainScoped.ValidateWorkforceProfile(ctx, profile) },
		func() error {
			_, err := plainScoped.TerminateWorkforceProfile(ctx, profile.ID, "2026-08-01")
			return err
		},
		func() error { _, err := plainScoped.ListWorkforceAssignments(ctx, profile.ID); return err },
		func() error { return plainScoped.UpsertWorkforceAssignment(ctx, assignment) },
		func() error { return plainScoped.ValidateWorkforceAssignment(ctx, assignment) },
	} {
		if err := call(); apperror.CodeOf(err) != "backend.identity.workforce_unavailable" {
			t.Fatalf("unavailable %d=%v", index, err)
		}
	}
	workforceOnly := NewIdentityApplicationService(&onboardingWorkforceOnlyRepository{identityScopedRepository: &identityScopedRepository{}}, nil)
	if _, err := workforceOnly.TerminateWorkforceProfile(ctx, profile.ID, "2026-08-01"); apperror.CodeOf(err) != "backend.identity.workforce_termination_unavailable" {
		t.Fatalf("termination capability=%v", err)
	}

	repository.loadErr = errors.New("profile")
	if _, _, err := service.GetWorkforceDetail(ctx, profile.ID); !errors.Is(err, repository.loadErr) {
		t.Fatalf("detail profile error=%v", err)
	}
	repository.loadErr, repository.found = nil, false
	if _, found, err := service.GetWorkforceDetail(ctx, profile.ID); err != nil || found {
		t.Fatalf("detail missing found=%v err=%v", found, err)
	}
	repository.found = true
	repository.getUserErr = errors.New("user")
	if _, _, err := service.GetWorkforceDetail(ctx, profile.ID); !errors.Is(err, repository.getUserErr) {
		t.Fatalf("detail user error=%v", err)
	}
	repository.getUserErr = nil
	repository.identityScopedRepository.users = nil
	if _, _, err := service.GetWorkforceDetail(ctx, profile.ID); apperror.CodeOf(err) != "backend.identity.workforce_user_not_found" {
		t.Fatalf("detail user missing=%v", err)
	}
	repository.identityScopedRepository.users = []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}}
	repository.listErr = errors.New("assignments")
	if _, _, err := service.GetWorkforceDetail(ctx, profile.ID); !errors.Is(err, repository.listErr) {
		t.Fatalf("detail assignments error=%v", err)
	}
	repository.listErr = nil
	repository.bindingsErr = errors.New("bindings")
	if _, _, err := service.GetWorkforceDetail(ctx, profile.ID); !errors.Is(err, repository.bindingsErr) {
		t.Fatalf("detail bindings error=%v", err)
	}
	repository.bindingsErr = nil

	invalidProfile := profile
	invalidProfile.OrganizationID = ""
	if err := service.ValidateWorkforceProfile(ctx, invalidProfile); apperror.CodeOf(err) != "backend.identity.workforce_profile_invalid" {
		t.Fatalf("invalid profile=%v", err)
	}
	if err := service.UpsertWorkforceProfile(ctx, invalidProfile); apperror.CodeOf(err) != "backend.identity.workforce_profile_invalid" {
		t.Fatalf("upsert invalid profile=%v", err)
	}
	invalidAssignment := assignment
	invalidAssignment.ID = ""
	if err := service.ValidateWorkforceAssignment(ctx, invalidAssignment); apperror.CodeOf(err) != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("invalid assignment=%v", err)
	}
	if err := service.UpsertWorkforceAssignment(ctx, invalidAssignment); apperror.CodeOf(err) != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("upsert invalid assignment=%v", err)
	}

	if _, err := service.TerminateWorkforceProfile(ctx, profile.ID, "bad"); apperror.CodeOf(err) != "backend.identity.workforce_termination_date_invalid" {
		t.Fatalf("termination preparation=%v", err)
	}
	repository.terminationErr = errors.New("terminate")
	if _, err := service.TerminateWorkforceProfile(ctx, profile.ID, "2026-08-01"); !errors.Is(err, repository.terminationErr) {
		t.Fatalf("termination error=%v", err)
	}
}

func workforceTransferBatchRequest(key string) IdentityWorkforceTransferBatchRequest {
	return IdentityWorkforceTransferBatchRequest{
		IdempotencyKey: key,
		Items: []identitymodel.IdentityWorkforceTransferBatchItem{{
			ProfileID: " workforce-1 ", PreviousAssignmentID: " old-primary ",
			Assignment:  identitymodel.IdentityWorkforceAssignment{ID: " new-primary ", OrganizationUnitID: " unit-new "},
			EffectiveAt: " 2026-08-01 ", Reason: " move ",
		}},
	}
}

func TestWorkforceTransferBatchPersistsReplaysAndRejectsEveryBoundary(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "default")
	service, repository := lifecycleApplicationFixture()
	actor := identitymodel.Principal{Known: true, UserID: " admin ", WorkspaceID: "default"}
	request := workforceTransferBatchRequest("batch")
	receipt, err := service.ApplyWorkforceTransferBatch(ctx, request, actor)
	if err != nil || receipt.Replayed || len(repository.transferApplied.Mutations) != 1 ||
		repository.transferApplied.ActorID != "admin" || repository.transferApplied.Items[0].Reason != "move" {
		t.Fatalf("receipt=%#v mutation=%#v err=%v", receipt, repository.transferApplied, err)
	}
	replay, err := service.ApplyWorkforceTransferBatch(ctx, request, actor)
	if err != nil || !replay.Replayed {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	reused := request
	reused.Items[0].Reason = "different"
	if _, err := service.ApplyWorkforceTransferBatch(ctx, reused, actor); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("reused key=%v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := service.ApplyWorkforceTransferBatch(canceled, workforceTransferBatchRequest("cancel"), actor); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
	unknown := actor
	unknown.Known = false
	if _, err := service.ApplyWorkforceTransferBatch(ctx, workforceTransferBatchRequest("unknown"), unknown); apperror.CodeOf(err) != "backend.identity.entitlement_actor_required" {
		t.Fatalf("unknown actor=%v", err)
	}
	blankActor := actor
	blankActor.UserID = " "
	if _, err := service.ApplyWorkforceTransferBatch(ctx, workforceTransferBatchRequest("blank-actor"), blankActor); apperror.CodeOf(err) != "backend.identity.entitlement_actor_required" {
		t.Fatalf("blank actor=%v", err)
	}
	for _, invalid := range []IdentityWorkforceTransferBatchRequest{
		{Items: request.Items},
		{IdempotencyKey: "empty"},
	} {
		if _, err := service.ApplyWorkforceTransferBatch(ctx, invalid, actor); apperror.CodeOf(err) != "backend.identity.workforce_transfer_batch_invalid" {
			t.Fatalf("invalid request=%#v err=%v", invalid, err)
		}
	}
	if _, err := service.ApplyWorkforceTransferBatch(t.Context(), workforceTransferBatchRequest("scope"), actor); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("missing scope=%v", err)
	}
	unavailable := NewIdentityApplicationService(&onboardingWorkforceOnlyRepository{identityScopedRepository: &identityScopedRepository{}}, nil)
	if _, err := unavailable.ApplyWorkforceTransferBatch(ctx, workforceTransferBatchRequest("unavailable"), actor); apperror.CodeOf(err) != "backend.identity.workforce_transfer_batch_unavailable" {
		t.Fatalf("unavailable=%v", err)
	}

	repository.transferReceiptErr = errors.New("receipt")
	if _, err := service.ApplyWorkforceTransferBatch(ctx, workforceTransferBatchRequest("receipt-error"), actor); !errors.Is(err, repository.transferReceiptErr) {
		t.Fatalf("receipt error=%v", err)
	}
	repository.transferReceiptErr = nil
	duplicate := workforceTransferBatchRequest("duplicate")
	duplicate.Items = append(duplicate.Items, duplicate.Items[0])
	if _, err := service.ApplyWorkforceTransferBatch(ctx, duplicate, actor); apperror.CodeOf(err) != "backend.identity.workforce_transfer_batch_duplicate_profile" {
		t.Fatalf("duplicate=%v", err)
	}
	badDate := workforceTransferBatchRequest("bad-date")
	badDate.Items[0].EffectiveAt = "bad"
	if _, err := service.ApplyWorkforceTransferBatch(ctx, badDate, actor); apperror.CodeOf(err) != "backend.identity.workforce_lifecycle_effective_date_invalid" {
		t.Fatalf("date=%v", err)
	}

	repository.loadErr = errors.New("profile")
	if _, err := service.ApplyWorkforceTransferBatch(ctx, workforceTransferBatchRequest("profile-error"), actor); !errors.Is(err, repository.loadErr) {
		t.Fatalf("profile error=%v", err)
	}
	repository.loadErr, repository.found = nil, false
	if _, err := service.ApplyWorkforceTransferBatch(ctx, workforceTransferBatchRequest("profile-missing"), actor); apperror.CodeOf(err) != "backend.identity.workforce_profile_not_found" {
		t.Fatalf("profile missing=%v", err)
	}
	repository.found = true
	repository.assignmentErr = errors.New("previous")
	if _, err := service.ApplyWorkforceTransferBatch(ctx, workforceTransferBatchRequest("previous-error"), actor); !errors.Is(err, repository.assignmentErr) {
		t.Fatalf("previous error=%v", err)
	}
	repository.assignmentErr, repository.assignmentFound = nil, false
	if _, err := service.ApplyWorkforceTransferBatch(ctx, workforceTransferBatchRequest("previous-missing"), actor); apperror.CodeOf(err) != "backend.identity.workforce_transfer_source_invalid" {
		t.Fatalf("previous missing=%v", err)
	}
	repository.assignmentFound = true
	for name, mutate := range map[string]func(*identitymodel.IdentityWorkforceAssignment){
		"profile": func(a *identitymodel.IdentityWorkforceAssignment) { a.WorkforceProfileID = "other" },
		"type": func(a *identitymodel.IdentityWorkforceAssignment) {
			a.AssignmentType = identitymodel.IdentityWorkforceAssignmentSecondary
		},
		"status": func(a *identitymodel.IdentityWorkforceAssignment) { a.Status = identitymodel.IdentityStatusDisabled },
	} {
		original := repository.assignment
		mutate(&repository.assignment)
		if _, err := service.ApplyWorkforceTransferBatch(ctx, workforceTransferBatchRequest("previous-"+name), actor); apperror.CodeOf(err) != "backend.identity.workforce_transfer_source_invalid" {
			t.Fatalf("%s previous=%v", name, err)
		}
		repository.assignment = original
	}
	badAssignment := workforceTransferBatchRequest("bad-assignment")
	badAssignment.Items[0].Assignment.ID = ""
	if _, err := service.ApplyWorkforceTransferBatch(ctx, badAssignment, actor); apperror.CodeOf(err) != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("assignment=%v", err)
	}
	repository.transferApplyErr = errors.New("apply")
	if _, err := service.ApplyWorkforceTransferBatch(ctx, workforceTransferBatchRequest("apply-error"), actor); !errors.Is(err, repository.transferApplyErr) {
		t.Fatalf("apply error=%v", err)
	}
}
