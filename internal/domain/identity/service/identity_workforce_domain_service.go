package service

import (
	"context"
	"errors"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type IdentityWorkforceDomainService struct {
	users     identityrepository.IdentityUserLookupRepository
	workforce identityrepository.IdentityWorkforceRepository
	workspace string
}

func NewIdentityWorkforceDomainService(users identityrepository.IdentityUserLookupRepository, workforce identityrepository.IdentityWorkforceRepository) *IdentityWorkforceDomainService {
	return &IdentityWorkforceDomainService{users: users, workforce: workforce}
}

func (s *IdentityWorkforceDomainService) ForWorkspace(workspaceID string) (*IdentityWorkforceDomainService, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	clone := *s
	clone.workspace = workspace.String()
	return &clone, nil
}

func (s *IdentityWorkforceDomainService) UpsertProfile(ctx context.Context, profile identitymodel.IdentityWorkforceProfile) error {
	if err := s.ValidateProfile(ctx, profile); err != nil {
		return err
	}
	if err := s.workforce.UpsertIdentityWorkforceProfile(ctx, s.workspace, profile); err != nil {
		return internalError("upsert workforce profile", err)
	}
	return nil
}

func (s *IdentityWorkforceDomainService) ValidateProfile(ctx context.Context, profile identitymodel.IdentityWorkforceProfile) error {
	if err := validateIdentityWorkforceProfile(profile); err != nil {
		return err
	}
	if s.users == nil || s.workforce == nil {
		return internalError("identity workforce dependencies", nil)
	}
	user, found, err := s.users.GetIdentityUser(ctx, s.workspace, profile.IdentityUserID)
	if err != nil {
		return internalError("load workforce identity user", err)
	}
	if !found || user.Status == identitymodel.IdentityStatusDeleted {
		return notFound("backend.identity.workforce_user_not_found", "user_id", profile.IdentityUserID)
	}
	return nil
}

func (s *IdentityWorkforceDomainService) TerminateProfile(ctx context.Context, profileID, effectiveAt string) (identitymodel.IdentityWorkforceProfile, error) {
	profile, err := s.PrepareProfileTermination(ctx, profileID, effectiveAt)
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, err
	}
	if err := s.workforce.UpsertIdentityWorkforceProfile(ctx, s.workspace, profile); err != nil {
		return identitymodel.IdentityWorkforceProfile{}, internalError("terminate workforce profile", err)
	}
	return profile, nil
}

func (s *IdentityWorkforceDomainService) PrepareProfileTermination(ctx context.Context, profileID, effectiveAt string) (identitymodel.IdentityWorkforceProfile, error) {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return identitymodel.IdentityWorkforceProfile{}, badRequest("backend.identity.workforce_profile_invalid")
	}
	if _, set, err := parseIdentityWorkforceDate(effectiveAt); err != nil || !set {
		return identitymodel.IdentityWorkforceProfile{}, badRequest("backend.identity.workforce_termination_date_invalid")
	}
	if s.workforce == nil {
		return identitymodel.IdentityWorkforceProfile{}, internalError("identity workforce repository", nil)
	}
	profile, found, err := s.workforce.GetIdentityWorkforceProfile(ctx, s.workspace, profileID)
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, internalError("load workforce profile", err)
	}
	if !found {
		return identitymodel.IdentityWorkforceProfile{}, notFound("backend.identity.workforce_profile_not_found", "profile_id", profileID)
	}
	effectiveAt = strings.TrimSpace(effectiveAt)
	profile.WorkStatus = identitymodel.IdentityWorkTerminated
	profile.EndDate = effectiveAt
	return profile, nil
}

func (s *IdentityWorkforceDomainService) UpsertAssignment(ctx context.Context, assignment identitymodel.IdentityWorkforceAssignment) error {
	if err := s.ValidateAssignment(ctx, assignment); err != nil {
		return err
	}
	if err := s.workforce.UpsertIdentityWorkforceAssignment(ctx, s.workspace, assignment); err != nil {
		return internalError("upsert workforce assignment", err)
	}
	return nil
}

func (s *IdentityWorkforceDomainService) ValidateAssignment(ctx context.Context, assignment identitymodel.IdentityWorkforceAssignment) error {
	if err := validateIdentityWorkforceAssignment(assignment); err != nil {
		return err
	}
	if s.workforce == nil {
		return internalError("identity workforce repository", nil)
	}
	profile, found, err := s.workforce.GetIdentityWorkforceProfile(ctx, s.workspace, assignment.WorkforceProfileID)
	if err != nil {
		return internalError("load workforce profile", err)
	}
	if !found {
		return notFound("backend.identity.workforce_profile_not_found", "profile_id", assignment.WorkforceProfileID)
	}
	return s.ValidateAssignmentAgainstProfile(ctx, assignment, profile)
}

func (s *IdentityWorkforceDomainService) ValidateAssignmentAgainstProfile(ctx context.Context, assignment identitymodel.IdentityWorkforceAssignment, profile identitymodel.IdentityWorkforceProfile, ignoredAssignmentIDs ...string) error {
	if err := validateIdentityWorkforceAssignment(assignment); err != nil {
		return err
	}
	if s.workforce == nil {
		return internalError("identity workforce repository", nil)
	}
	if assignment.WorkforceProfileID != profile.ID {
		return badRequest("backend.identity.workforce_assignment_profile_mismatch")
	}
	if assignment.Status == identitymodel.IdentityStatusActive && profile.WorkStatus != identitymodel.IdentityWorkActive {
		return conflict("backend.identity.workforce_profile_inactive", "profile_id", profile.ID)
	}
	if managerID := strings.TrimSpace(assignment.ManagerWorkforceProfileID); managerID != "" {
		if managerID == profile.ID {
			return badRequest("backend.identity.workforce_manager_self_reference", "profile_id", profile.ID)
		}
		manager, managerFound, managerErr := s.workforce.GetIdentityWorkforceProfile(ctx, s.workspace, managerID)
		if managerErr != nil {
			return internalError("load workforce manager", managerErr)
		}
		if !managerFound || manager.OrganizationID != profile.OrganizationID || manager.WorkStatus != identitymodel.IdentityWorkActive {
			return badRequest("backend.identity.workforce_manager_invalid", "manager_profile_id", managerID)
		}
	}
	assignments, err := s.workforce.ListIdentityWorkforceAssignments(ctx, s.workspace, profile.ID)
	if err != nil {
		return internalError("list workforce assignments", err)
	}
	if assignment.AssignmentType == identitymodel.IdentityWorkforceAssignmentPrimary && assignment.Status == identitymodel.IdentityStatusActive {
		ignored := map[string]bool{}
		for _, assignmentID := range ignoredAssignmentIDs {
			ignored[strings.TrimSpace(assignmentID)] = true
		}
		for _, existing := range assignments {
			if existing.ID != assignment.ID && !ignored[existing.ID] &&
				existing.AssignmentType == identitymodel.IdentityWorkforceAssignmentPrimary &&
				existing.Status == identitymodel.IdentityStatusActive &&
				identityWorkforcePeriodsOverlap(existing.EffectiveFrom, existing.EffectiveTo, assignment.EffectiveFrom, assignment.EffectiveTo) {
				return conflict("backend.identity.workforce_primary_assignment_conflict", "assignment_id", existing.ID)
			}
		}
	}
	return nil
}

func (s *IdentityWorkforceDomainService) ValidateLifecycleEffectiveDate(value string) error {
	if _, set, err := parseIdentityWorkforceDate(value); err != nil || !set {
		return badRequest("backend.identity.workforce_lifecycle_effective_date_invalid")
	}
	return nil
}

func validateIdentityWorkforceProfile(profile identitymodel.IdentityWorkforceProfile) error {
	if strings.TrimSpace(profile.ID) == "" || strings.TrimSpace(profile.OrganizationID) == "" ||
		strings.TrimSpace(profile.IdentityUserID) == "" || strings.TrimSpace(profile.WorkerNo) == "" {
		return badRequest("backend.identity.workforce_profile_invalid")
	}
	switch profile.WorkerType {
	case identitymodel.IdentityWorkerEmployee, identitymodel.IdentityWorkerContractor, identitymodel.IdentityWorkerPartnerStaff, identitymodel.IdentityWorkerTemporary:
	default:
		return badRequest("backend.identity.workforce_worker_type_invalid")
	}
	switch profile.WorkStatus {
	case identitymodel.IdentityWorkPending, identitymodel.IdentityWorkActive, identitymodel.IdentityWorkSuspended, identitymodel.IdentityWorkTerminated:
	default:
		return badRequest("backend.identity.workforce_status_invalid")
	}
	return validateIdentityWorkforcePeriod(profile.StartDate, profile.EndDate)
}

func validateIdentityWorkforceAssignment(assignment identitymodel.IdentityWorkforceAssignment) error {
	if strings.TrimSpace(assignment.ID) == "" || strings.TrimSpace(assignment.WorkforceProfileID) == "" || strings.TrimSpace(assignment.OrganizationUnitID) == "" {
		return badRequest("backend.identity.workforce_assignment_invalid")
	}
	switch assignment.AssignmentType {
	case identitymodel.IdentityWorkforceAssignmentPrimary, identitymodel.IdentityWorkforceAssignmentSecondary,
		identitymodel.IdentityWorkforceAssignmentTemporary, identitymodel.IdentityWorkforceAssignmentActing:
	default:
		return badRequest("backend.identity.workforce_assignment_type_invalid")
	}
	switch assignment.Status {
	case identitymodel.IdentityStatusActive, identitymodel.IdentityStatusDisabled:
	default:
		return badRequest("backend.identity.workforce_assignment_status_invalid")
	}
	return validateIdentityWorkforcePeriod(assignment.EffectiveFrom, assignment.EffectiveTo)
}

func validateIdentityWorkforcePeriod(from, to string) error {
	start, startSet, err := parseIdentityWorkforceDate(from)
	if err != nil {
		return badRequest("backend.identity.workforce_effective_from_invalid")
	}
	end, endSet, err := parseIdentityWorkforceDate(to)
	if err != nil {
		return badRequest("backend.identity.workforce_effective_to_invalid")
	}
	if startSet && endSet && end.Before(start) {
		return badRequest("backend.identity.workforce_period_invalid")
	}
	return nil
}

func parseIdentityWorkforceDate(value string) (time.Time, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false, nil
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true, nil
		}
	}
	return time.Time{}, true, errors.New("invalid workforce date")
}

func identityWorkforcePeriodsOverlap(leftFrom, leftTo, rightFrom, rightTo string) bool {
	leftStart, _, _ := parseIdentityWorkforceDate(leftFrom)
	leftEnd, leftEndSet, _ := parseIdentityWorkforceDate(leftTo)
	rightStart, _, _ := parseIdentityWorkforceDate(rightFrom)
	rightEnd, rightEndSet, _ := parseIdentityWorkforceDate(rightTo)
	return (!leftEndSet || !leftEnd.Before(rightStart)) && (!rightEndSet || !rightEnd.Before(leftStart))
}
