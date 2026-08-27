package service

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityWorkforceRepositoryStub struct {
	users        map[string]identitymodel.IdentityUser
	profiles     map[string]identitymodel.IdentityWorkforceProfile
	assignments  map[string]identitymodel.IdentityWorkforceAssignment
	userErr      error
	profileErr   error
	profileErrID string
	listErr      error
	writeErr     error
}

func (r *identityWorkforceRepositoryStub) GetIdentityUser(context.Context, string, string) (identitymodel.IdentityUser, bool, error) {
	if r.userErr != nil {
		return identitymodel.IdentityUser{}, false, r.userErr
	}
	user, ok := r.users["user"]
	return user, ok, nil
}

func (r *identityWorkforceRepositoryStub) ListIdentityWorkforceProfiles(context.Context, string) ([]identitymodel.IdentityWorkforceProfile, error) {
	out := make([]identitymodel.IdentityWorkforceProfile, 0, len(r.profiles))
	for _, profile := range r.profiles {
		out = append(out, profile)
	}
	return out, nil
}

func (r *identityWorkforceRepositoryStub) GetIdentityWorkforceProfile(_ context.Context, _, profileID string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	if r.profileErr != nil && (r.profileErrID == "" || r.profileErrID == profileID) {
		return identitymodel.IdentityWorkforceProfile{}, false, r.profileErr
	}
	profile, ok := r.profiles[profileID]
	return profile, ok, nil
}

func (r *identityWorkforceRepositoryStub) UpsertIdentityWorkforceProfile(_ context.Context, _ string, profile identitymodel.IdentityWorkforceProfile) error {
	if r.writeErr != nil {
		return r.writeErr
	}
	r.profiles[profile.ID] = profile
	return nil
}

func (r *identityWorkforceRepositoryStub) ListIdentityWorkforceAssignments(_ context.Context, _, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	out := []identitymodel.IdentityWorkforceAssignment{}
	for _, assignment := range r.assignments {
		if profileID == "" || assignment.WorkforceProfileID == profileID {
			out = append(out, assignment)
		}
	}
	return out, nil
}

func (r *identityWorkforceRepositoryStub) GetIdentityWorkforceAssignment(_ context.Context, _, assignmentID string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	assignment, ok := r.assignments[assignmentID]
	return assignment, ok, nil
}

func (r *identityWorkforceRepositoryStub) UpsertIdentityWorkforceAssignment(_ context.Context, _ string, assignment identitymodel.IdentityWorkforceAssignment) error {
	if r.writeErr != nil {
		return r.writeErr
	}
	r.assignments[assignment.ID] = assignment
	return nil
}

func TestIdentityWorkforceDomainServiceSupportsProfileAndAssignmentKinds(t *testing.T) {
	repository := newIdentityWorkforceRepositoryStub()
	service := scopedIdentityWorkforceService(t, repository)
	profile := validIdentityWorkforceProfile()
	if err := service.UpsertProfile(t.Context(), profile); err != nil {
		t.Fatal(err)
	}
	manager := profile
	manager.ID, manager.IdentityUserID, manager.WorkerNo = "manager", "manager-user", "E-002"
	repository.profiles[manager.ID] = manager

	for index, assignmentType := range []identitymodel.IdentityWorkforceAssignmentType{
		identitymodel.IdentityWorkforceAssignmentPrimary,
		identitymodel.IdentityWorkforceAssignmentSecondary,
		identitymodel.IdentityWorkforceAssignmentTemporary,
		identitymodel.IdentityWorkforceAssignmentActing,
	} {
		assignment := validIdentityWorkforceAssignment()
		assignment.ID = "assignment-" + string(rune('a'+index))
		assignment.AssignmentType = assignmentType
		if assignmentType != identitymodel.IdentityWorkforceAssignmentPrimary {
			assignment.ManagerWorkforceProfileID = "manager"
		}
		if err := service.UpsertAssignment(t.Context(), assignment); err != nil {
			t.Fatalf("assignment type %s: %v", assignmentType, err)
		}
	}
	if len(repository.assignments) != 4 {
		t.Fatalf("assignments=%#v", repository.assignments)
	}
}

func TestIdentityWorkforceTerminationIsIndependentAndIdempotent(t *testing.T) {
	repository := newIdentityWorkforceRepositoryStub()
	service := scopedIdentityWorkforceService(t, repository)
	profile := validIdentityWorkforceProfile()
	repository.profiles[profile.ID] = profile

	terminated, err := service.TerminateProfile(t.Context(), profile.ID, "2026-07-25")
	if err != nil || terminated.WorkStatus != identitymodel.IdentityWorkTerminated || terminated.EndDate != "2026-07-25" {
		t.Fatalf("terminated=%#v err=%v", terminated, err)
	}
	replayed, err := service.TerminateProfile(t.Context(), profile.ID, "2026-07-25")
	if err != nil || replayed != terminated {
		t.Fatalf("replayed=%#v err=%v", replayed, err)
	}
	if repository.users["user"].Status != identitymodel.IdentityStatusActive {
		t.Fatalf("workforce termination changed account=%#v", repository.users["user"])
	}
}

func TestIdentityWorkforceTerminationRejectsInvalidAndUnavailableTargets(t *testing.T) {
	repository := newIdentityWorkforceRepositoryStub()
	service := scopedIdentityWorkforceService(t, repository)
	for _, test := range []struct {
		name      string
		profileID string
		date      string
		code      string
	}{
		{"blank profile", "", "2026-07-25", "backend.identity.workforce_profile_invalid"},
		{"blank date", "profile", "", "backend.identity.workforce_termination_date_invalid"},
		{"invalid date", "profile", "tomorrow", "backend.identity.workforce_termination_date_invalid"},
		{"missing profile", "missing", "2026-07-25", "backend.identity.workforce_profile_not_found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := service.TerminateProfile(t.Context(), test.profileID, test.date); apperror.CodeOf(err) != test.code {
				t.Fatalf("err=%v code=%q", err, apperror.CodeOf(err))
			}
		})
	}
	repository.profileErr = errors.New("read")
	if _, err := service.TerminateProfile(t.Context(), "profile", "2026-07-25"); apperror.KindOf(err) != apperror.KindInternal {
		t.Fatalf("read err=%v", err)
	}
	repository.profileErr = nil
	profile := validIdentityWorkforceProfile()
	repository.profiles[profile.ID] = profile
	repository.writeErr = errors.New("write")
	if _, err := service.TerminateProfile(t.Context(), profile.ID, "2026-07-25"); apperror.KindOf(err) != apperror.KindInternal {
		t.Fatalf("write err=%v", err)
	}
	if _, err := (&IdentityWorkforceDomainService{}).TerminateProfile(t.Context(), "profile", "2026-07-25"); apperror.KindOf(err) != apperror.KindInternal {
		t.Fatalf("repository err=%v", err)
	}
}

func TestIdentityWorkforceDomainServiceRejectsInvalidProfileContracts(t *testing.T) {
	repository := newIdentityWorkforceRepositoryStub()
	service := scopedIdentityWorkforceService(t, repository)
	valid := validIdentityWorkforceProfile()
	tests := []struct {
		name string
		code string
		edit func(*identitymodel.IdentityWorkforceProfile)
	}{
		{name: "required", code: "backend.identity.workforce_profile_invalid", edit: func(value *identitymodel.IdentityWorkforceProfile) { value.ID = "" }},
		{name: "worker type", code: "backend.identity.workforce_worker_type_invalid", edit: func(value *identitymodel.IdentityWorkforceProfile) { value.WorkerType = "unknown" }},
		{name: "status", code: "backend.identity.workforce_status_invalid", edit: func(value *identitymodel.IdentityWorkforceProfile) { value.WorkStatus = "unknown" }},
		{name: "start", code: "backend.identity.workforce_effective_from_invalid", edit: func(value *identitymodel.IdentityWorkforceProfile) { value.StartDate = "invalid" }},
		{name: "end", code: "backend.identity.workforce_effective_to_invalid", edit: func(value *identitymodel.IdentityWorkforceProfile) { value.EndDate = "invalid" }},
		{name: "period", code: "backend.identity.workforce_period_invalid", edit: func(value *identitymodel.IdentityWorkforceProfile) { value.EndDate = "2025-01-01" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.edit(&value)
			if code := apperror.CodeOf(service.UpsertProfile(t.Context(), value)); code != test.code {
				t.Fatalf("code=%q want=%q", code, test.code)
			}
		})
	}
	delete(repository.users, "user")
	if code := apperror.CodeOf(service.UpsertProfile(t.Context(), valid)); code != "backend.identity.workforce_user_not_found" {
		t.Fatalf("missing user code=%q", code)
	}
}

func TestIdentityWorkforceDomainServiceRejectsInvalidAssignmentContracts(t *testing.T) {
	repository := newIdentityWorkforceRepositoryStub()
	service := scopedIdentityWorkforceService(t, repository)
	valid := validIdentityWorkforceAssignment()
	tests := []struct {
		name string
		code string
		edit func(*identitymodel.IdentityWorkforceAssignment)
	}{
		{name: "required", code: "backend.identity.workforce_assignment_invalid", edit: func(value *identitymodel.IdentityWorkforceAssignment) { value.OrganizationUnitID = "" }},
		{name: "type", code: "backend.identity.workforce_assignment_type_invalid", edit: func(value *identitymodel.IdentityWorkforceAssignment) { value.AssignmentType = "unknown" }},
		{name: "status", code: "backend.identity.workforce_assignment_status_invalid", edit: func(value *identitymodel.IdentityWorkforceAssignment) {
			value.Status = identitymodel.IdentityStatusDeleted
		}},
		{name: "period", code: "backend.identity.workforce_period_invalid", edit: func(value *identitymodel.IdentityWorkforceAssignment) { value.EffectiveTo = "2025-01-01" }},
		{name: "self manager", code: "backend.identity.workforce_manager_self_reference", edit: func(value *identitymodel.IdentityWorkforceAssignment) { value.ManagerWorkforceProfileID = "workforce" }},
		{name: "missing manager", code: "backend.identity.workforce_manager_invalid", edit: func(value *identitymodel.IdentityWorkforceAssignment) { value.ManagerWorkforceProfileID = "missing" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.edit(&value)
			if code := apperror.CodeOf(service.UpsertAssignment(t.Context(), value)); code != test.code {
				t.Fatalf("code=%q want=%q", code, test.code)
			}
		})
	}
	delete(repository.profiles, "workforce")
	if code := apperror.CodeOf(service.UpsertAssignment(t.Context(), valid)); code != "backend.identity.workforce_profile_not_found" {
		t.Fatalf("missing profile code=%q", code)
	}
}

func TestIdentityWorkforceDomainServiceRejectsOverlappingPrimaryAssignment(t *testing.T) {
	repository := newIdentityWorkforceRepositoryStub()
	repository.assignments["existing"] = identitymodel.IdentityWorkforceAssignment{
		ID: "existing", WorkforceProfileID: "workforce", OrganizationUnitID: "unit-a",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary,
		EffectiveFrom:  "2026-01-01", EffectiveTo: "2026-12-31", Status: identitymodel.IdentityStatusActive,
	}
	service := scopedIdentityWorkforceService(t, repository)
	overlap := validIdentityWorkforceAssignment()
	overlap.EffectiveFrom, overlap.EffectiveTo = "2026-06-01", "2027-01-01"
	if code := apperror.CodeOf(service.UpsertAssignment(t.Context(), overlap)); code != "backend.identity.workforce_primary_assignment_conflict" {
		t.Fatalf("overlap code=%q", code)
	}
	overlap.EffectiveFrom, overlap.EffectiveTo = "2027-01-01", "2027-12-31"
	if err := service.UpsertAssignment(t.Context(), overlap); err != nil {
		t.Fatalf("non-overlap rejected: %v", err)
	}
}

func TestIdentityWorkforceDomainServiceMapsDependencyFailures(t *testing.T) {
	failure := errors.New("store failure")
	repository := newIdentityWorkforceRepositoryStub()
	service := scopedIdentityWorkforceService(t, repository)
	repository.userErr = failure
	if code := apperror.CodeOf(service.UpsertProfile(t.Context(), validIdentityWorkforceProfile())); code != "backend.internal" {
		t.Fatalf("user failure code=%q", code)
	}
	repository.userErr, repository.writeErr = nil, failure
	if code := apperror.CodeOf(service.UpsertProfile(t.Context(), validIdentityWorkforceProfile())); code != "backend.internal" {
		t.Fatalf("profile write failure code=%q", code)
	}
	repository.writeErr, repository.profileErr = nil, failure
	if code := apperror.CodeOf(service.UpsertAssignment(t.Context(), validIdentityWorkforceAssignment())); code != "backend.internal" {
		t.Fatalf("profile read failure code=%q", code)
	}
	repository.profileErr, repository.listErr = nil, failure
	if code := apperror.CodeOf(service.UpsertAssignment(t.Context(), validIdentityWorkforceAssignment())); code != "backend.internal" {
		t.Fatalf("assignment list failure code=%q", code)
	}
	repository.listErr, repository.writeErr = nil, failure
	if code := apperror.CodeOf(service.UpsertAssignment(t.Context(), validIdentityWorkforceAssignment())); code != "backend.internal" {
		t.Fatalf("assignment write failure code=%q", code)
	}
	if code := apperror.CodeOf(NewIdentityWorkforceDomainService(nil, nil).UpsertProfile(t.Context(), validIdentityWorkforceProfile())); code != "backend.internal" {
		t.Fatalf("missing dependencies code=%q", code)
	}
	if code := apperror.CodeOf(NewIdentityWorkforceDomainService(nil, nil).UpsertAssignment(t.Context(), validIdentityWorkforceAssignment())); code != "backend.internal" {
		t.Fatalf("missing assignment dependency code=%q", code)
	}
}

func TestIdentityWorkforceDomainServiceAssignmentEligibilityEdges(t *testing.T) {
	repository := newIdentityWorkforceRepositoryStub()
	service := scopedIdentityWorkforceService(t, repository)
	profile := repository.profiles["workforce"]
	profile.WorkStatus = identitymodel.IdentityWorkSuspended
	repository.profiles["workforce"] = profile
	if code := apperror.CodeOf(service.UpsertAssignment(t.Context(), validIdentityWorkforceAssignment())); code != "backend.identity.workforce_profile_inactive" {
		t.Fatalf("inactive profile code=%q", code)
	}
	profile.WorkStatus = identitymodel.IdentityWorkActive
	repository.profiles["workforce"] = profile
	manager := profile
	manager.ID = "manager"
	manager.OrganizationID = "other"
	repository.profiles["manager"] = manager
	assignment := validIdentityWorkforceAssignment()
	assignment.ManagerWorkforceProfileID = "manager"
	if code := apperror.CodeOf(service.UpsertAssignment(t.Context(), assignment)); code != "backend.identity.workforce_manager_invalid" {
		t.Fatalf("cross-organization manager code=%q", code)
	}
	manager.OrganizationID = profile.OrganizationID
	manager.WorkStatus = identitymodel.IdentityWorkSuspended
	repository.profiles["manager"] = manager
	if code := apperror.CodeOf(service.UpsertAssignment(t.Context(), assignment)); code != "backend.identity.workforce_manager_invalid" {
		t.Fatalf("inactive manager code=%q", code)
	}
	repository.profileErr = errors.New("manager lookup failure")
	repository.profileErrID = "manager"
	if code := apperror.CodeOf(service.UpsertAssignment(t.Context(), assignment)); code != "backend.internal" {
		t.Fatalf("manager lookup code=%q", code)
	}
}

func TestIdentityWorkforceDomainServiceDateAndScopeEdges(t *testing.T) {
	if _, err := NewIdentityWorkforceDomainService(nil, nil).ForWorkspace(" "); err == nil {
		t.Fatal("empty workspace accepted")
	}
	for _, period := range [][2]string{
		{"", ""},
		{"2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"},
		{"", "2026-01-02"},
		{"2026-01-01", ""},
	} {
		if err := validateIdentityWorkforcePeriod(period[0], period[1]); err != nil {
			t.Fatalf("period=%v err=%v", period, err)
		}
	}
}

func TestIdentityWorkforceDomainServiceRemainingDependencyAndShortCircuitEdges(t *testing.T) {
	repository := newIdentityWorkforceRepositoryStub()
	profile := validIdentityWorkforceProfile()
	assignment := validIdentityWorkforceAssignment()

	if code := apperror.CodeOf(NewIdentityWorkforceDomainService(repository, nil).
		ValidateProfile(t.Context(), profile)); code != "backend.internal" {
		t.Fatalf("missing workforce dependency code=%q", code)
	}
	deleted := repository.users["user"]
	deleted.Status = identitymodel.IdentityStatusDeleted
	repository.users["user"] = deleted
	if code := apperror.CodeOf(scopedIdentityWorkforceService(t, repository).
		ValidateProfile(t.Context(), profile)); code != "backend.identity.workforce_user_not_found" {
		t.Fatalf("deleted user code=%q", code)
	}
	deleted.Status = identitymodel.IdentityStatusActive
	repository.users["user"] = deleted

	if code := apperror.CodeOf((&IdentityWorkforceDomainService{}).
		ValidateAssignmentAgainstProfile(t.Context(), assignment, profile)); code != "backend.internal" {
		t.Fatalf("missing assignment repository code=%q", code)
	}
	invalidAssignment := assignment
	invalidAssignment.OrganizationUnitID = ""
	if code := apperror.CodeOf(scopedIdentityWorkforceService(t, repository).
		ValidateAssignmentAgainstProfile(t.Context(), invalidAssignment, profile)); code != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("invalid assignment code=%q", code)
	}
	mismatch := assignment
	mismatch.WorkforceProfileID = "other-profile"
	if code := apperror.CodeOf(scopedIdentityWorkforceService(t, repository).
		ValidateAssignmentAgainstProfile(t.Context(), mismatch, profile)); code != "backend.identity.workforce_assignment_profile_mismatch" {
		t.Fatalf("profile mismatch code=%q", code)
	}

	disabled := assignment
	disabled.Status = identitymodel.IdentityStatusDisabled
	inactiveProfile := profile
	inactiveProfile.WorkStatus = identitymodel.IdentityWorkSuspended
	if err := scopedIdentityWorkforceService(t, repository).
		ValidateAssignmentAgainstProfile(t.Context(), disabled, inactiveProfile); err != nil {
		t.Fatalf("disabled assignment rejected for inactive profile: %v", err)
	}

	repository.assignments[assignment.ID] = assignment
	if err := scopedIdentityWorkforceService(t, repository).UpsertAssignment(t.Context(), assignment); err != nil {
		t.Fatalf("same assignment update rejected: %v", err)
	}
	existing := assignment
	existing.ID = "existing"
	repository.assignments = map[string]identitymodel.IdentityWorkforceAssignment{existing.ID: existing}
	if err := scopedIdentityWorkforceService(t, repository).
		ValidateAssignmentAgainstProfile(t.Context(), assignment, profile, existing.ID); err != nil {
		t.Fatalf("ignored assignment rejected: %v", err)
	}
	existing.AssignmentType = identitymodel.IdentityWorkforceAssignmentSecondary
	repository.assignments = map[string]identitymodel.IdentityWorkforceAssignment{existing.ID: existing}
	if err := scopedIdentityWorkforceService(t, repository).
		ValidateAssignmentAgainstProfile(t.Context(), assignment, profile); err != nil {
		t.Fatalf("secondary existing assignment rejected: %v", err)
	}
	existing.AssignmentType = identitymodel.IdentityWorkforceAssignmentPrimary
	existing.Status = identitymodel.IdentityStatusDisabled
	repository.assignments = map[string]identitymodel.IdentityWorkforceAssignment{existing.ID: existing}
	if err := scopedIdentityWorkforceService(t, repository).
		ValidateAssignmentAgainstProfile(t.Context(), assignment, profile); err != nil {
		t.Fatalf("disabled existing assignment rejected: %v", err)
	}
	if code := apperror.CodeOf(scopedIdentityWorkforceService(t, repository).
		ValidateLifecycleEffectiveDate(" ")); code != "backend.identity.workforce_lifecycle_effective_date_invalid" {
		t.Fatalf("blank lifecycle date code=%q", code)
	}
	if code := apperror.CodeOf(scopedIdentityWorkforceService(t, repository).
		ValidateLifecycleEffectiveDate("invalid")); code != "backend.identity.workforce_lifecycle_effective_date_invalid" {
		t.Fatalf("invalid lifecycle date code=%q", code)
	}
	if err := scopedIdentityWorkforceService(t, repository).ValidateLifecycleEffectiveDate("2026-07-27"); err != nil {
		t.Fatalf("valid lifecycle date error=%v", err)
	}

	blankWorker := profile
	blankWorker.WorkerNo = " "
	if code := apperror.CodeOf(validateIdentityWorkforceProfile(blankWorker)); code != "backend.identity.workforce_profile_invalid" {
		t.Fatalf("blank worker number code=%q", code)
	}
	blankOrganization := profile
	blankOrganization.OrganizationID = " "
	if code := apperror.CodeOf(validateIdentityWorkforceProfile(blankOrganization)); code != "backend.identity.workforce_profile_invalid" {
		t.Fatalf("blank organization code=%q", code)
	}
	blankUser := profile
	blankUser.IdentityUserID = " "
	if code := apperror.CodeOf(validateIdentityWorkforceProfile(blankUser)); code != "backend.identity.workforce_profile_invalid" {
		t.Fatalf("blank identity user code=%q", code)
	}
	blankProfile := assignment
	blankProfile.WorkforceProfileID = " "
	if code := apperror.CodeOf(validateIdentityWorkforceAssignment(blankProfile)); code != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("blank assignment profile code=%q", code)
	}
	blankAssignmentID := assignment
	blankAssignmentID.ID = " "
	if code := apperror.CodeOf(validateIdentityWorkforceAssignment(blankAssignmentID)); code != "backend.identity.workforce_assignment_invalid" {
		t.Fatalf("blank assignment ID code=%q", code)
	}
}

func newIdentityWorkforceRepositoryStub() *identityWorkforceRepositoryStub {
	return &identityWorkforceRepositoryStub{
		users: map[string]identitymodel.IdentityUser{"user": {ID: "user", Status: identitymodel.IdentityStatusActive}},
		profiles: map[string]identitymodel.IdentityWorkforceProfile{
			"workforce": validIdentityWorkforceProfile(),
		},
		assignments: map[string]identitymodel.IdentityWorkforceAssignment{},
	}
}

func scopedIdentityWorkforceService(t *testing.T, repository *identityWorkforceRepositoryStub) *IdentityWorkforceDomainService {
	t.Helper()
	service, err := NewIdentityWorkforceDomainService(repository, repository).ForWorkspace("workspace")
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func validIdentityWorkforceProfile() identitymodel.IdentityWorkforceProfile {
	return identitymodel.IdentityWorkforceProfile{
		ID: "workforce", OrganizationID: "organization", IdentityUserID: "user", WorkerNo: "E-001",
		WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
		StartDate: "2026-01-01", EndDate: "2028-01-01",
	}
}

func validIdentityWorkforceAssignment() identitymodel.IdentityWorkforceAssignment {
	return identitymodel.IdentityWorkforceAssignment{
		ID: "assignment", WorkforceProfileID: "workforce", OrganizationUnitID: "unit",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary,
		EffectiveFrom:  "2026-01-01", EffectiveTo: "2026-12-31", Status: identitymodel.IdentityStatusActive,
	}
}
