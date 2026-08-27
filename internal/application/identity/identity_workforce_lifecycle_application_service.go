package identity

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const (
	IdentityWorkforceLifecycleInvite       = "invite"
	IdentityWorkforceLifecycleOnboard      = "onboard"
	IdentityWorkforceLifecycleAssign       = "assign"
	IdentityWorkforceLifecycleTransfer     = "transfer"
	IdentityWorkforceLifecycleAddSecondary = "add_secondary"
	IdentityWorkforceLifecycleSuspend      = "suspend"
	IdentityWorkforceLifecycleRevokeAccess = "revoke_access"
)

type IdentityWorkforceLifecycleRequest struct {
	Operation            string                                    `json:"operation"`
	Profile              identitymodel.IdentityWorkforceProfile    `json:"profile"`
	Assignment           identitymodel.IdentityWorkforceAssignment `json:"assignment"`
	PreviousAssignmentID string                                    `json:"previous_assignment_id,omitempty"`
	EffectiveAt          string                                    `json:"effective_at,omitempty"`
	ActorID              string                                    `json:"actor_id,omitempty"`
	Reason               string                                    `json:"reason,omitempty"`
}

func (s *IdentityApplicationService) ApplyWorkforceLifecycle(ctx context.Context, request IdentityWorkforceLifecycleRequest) (identitymodel.IdentityWorkforceLifecycleResult, error) {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return identitymodel.IdentityWorkforceLifecycleResult{}, err
	}
	if scoped.WorkforceDomainService == nil || scoped.workforceLifecycle == nil {
		return identitymodel.IdentityWorkforceLifecycleResult{}, &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_lifecycle_unavailable"}
	}
	request.Operation = strings.TrimSpace(request.Operation)
	request.ActorID = strings.TrimSpace(request.ActorID)
	request.Reason = strings.TrimSpace(request.Reason)
	mutation := identitymodel.IdentityWorkforceLifecycleMutation{
		WorkspaceID: scoped.WorkspaceID(), ActorID: request.ActorID, Reason: request.Reason,
	}
	switch request.Operation {
	case IdentityWorkforceLifecycleInvite:
		request.Profile.WorkStatus = identitymodel.IdentityWorkPending
		if err := scoped.WorkforceDomainService.ValidateProfile(ctx, request.Profile); err != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, err
		}
		mutation.Profile = &request.Profile
	case IdentityWorkforceLifecycleOnboard:
		request.Profile.WorkStatus = identitymodel.IdentityWorkActive
		request.Assignment.WorkforceProfileID = request.Profile.ID
		request.Assignment.AssignmentType = identitymodel.IdentityWorkforceAssignmentPrimary
		request.Assignment.Status = identitymodel.IdentityStatusActive
		if err := scoped.WorkforceDomainService.ValidateProfile(ctx, request.Profile); err != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, err
		}
		if err := scoped.WorkforceDomainService.ValidateAssignmentAgainstProfile(ctx, request.Assignment, request.Profile); err != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, err
		}
		request.Profile.PrimaryAssignmentID = request.Assignment.ID
		mutation.Profile = &request.Profile
		mutation.UpsertAssignments = []identitymodel.IdentityWorkforceAssignment{request.Assignment}
	case IdentityWorkforceLifecycleAssign, IdentityWorkforceLifecycleAddSecondary:
		profile, found, loadErr := scoped.workforceRepository.GetIdentityWorkforceProfile(ctx, scoped.WorkspaceID(), request.Profile.ID)
		if loadErr != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, loadErr
		}
		if !found {
			return identitymodel.IdentityWorkforceLifecycleResult{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.workforce_profile_not_found"}
		}
		request.Assignment.WorkforceProfileID = profile.ID
		request.Assignment.Status = identitymodel.IdentityStatusActive
		if request.Operation == IdentityWorkforceLifecycleAddSecondary {
			request.Assignment.AssignmentType = identitymodel.IdentityWorkforceAssignmentSecondary
		} else if request.Assignment.AssignmentType == "" {
			request.Assignment.AssignmentType = identitymodel.IdentityWorkforceAssignmentTemporary
		}
		if err := scoped.WorkforceDomainService.ValidateAssignmentAgainstProfile(ctx, request.Assignment, profile); err != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, err
		}
		mutation.UpsertAssignments = []identitymodel.IdentityWorkforceAssignment{request.Assignment}
	case IdentityWorkforceLifecycleTransfer:
		if err := scoped.WorkforceDomainService.ValidateLifecycleEffectiveDate(request.EffectiveAt); err != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, err
		}
		profile, found, loadErr := scoped.workforceRepository.GetIdentityWorkforceProfile(ctx, scoped.WorkspaceID(), request.Profile.ID)
		if loadErr != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, loadErr
		}
		if !found {
			return identitymodel.IdentityWorkforceLifecycleResult{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.workforce_profile_not_found"}
		}
		previousID := strings.TrimSpace(request.PreviousAssignmentID)
		previous, previousFound, previousErr := scoped.workforceRepository.GetIdentityWorkforceAssignment(ctx, scoped.WorkspaceID(), previousID)
		if previousErr != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, previousErr
		}
		if !previousFound || previous.WorkforceProfileID != profile.ID || previous.AssignmentType != identitymodel.IdentityWorkforceAssignmentPrimary || previous.Status != identitymodel.IdentityStatusActive {
			return identitymodel.IdentityWorkforceLifecycleResult{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.workforce_transfer_source_invalid"}
		}
		request.Assignment.WorkforceProfileID = profile.ID
		request.Assignment.AssignmentType = identitymodel.IdentityWorkforceAssignmentPrimary
		request.Assignment.Status = identitymodel.IdentityStatusActive
		request.Assignment.EffectiveFrom = strings.TrimSpace(request.EffectiveAt)
		if err := scoped.WorkforceDomainService.ValidateAssignmentAgainstProfile(ctx, request.Assignment, profile, previous.ID); err != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, err
		}
		profile.PrimaryAssignmentID = request.Assignment.ID
		mutation.Profile = &profile
		mutation.EndAssignments = []identitymodel.IdentityWorkforceAssignmentEnd{{AssignmentID: previous.ID, EffectiveTo: request.Assignment.EffectiveFrom}}
		mutation.UpsertAssignments = []identitymodel.IdentityWorkforceAssignment{request.Assignment}
	case IdentityWorkforceLifecycleSuspend:
		if err := scoped.WorkforceDomainService.ValidateLifecycleEffectiveDate(request.EffectiveAt); err != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, err
		}
		profile, found, loadErr := scoped.workforceRepository.GetIdentityWorkforceProfile(ctx, scoped.WorkspaceID(), request.Profile.ID)
		if loadErr != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, loadErr
		}
		if !found {
			return identitymodel.IdentityWorkforceLifecycleResult{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.workforce_profile_not_found"}
		}
		profile.WorkStatus = identitymodel.IdentityWorkSuspended
		if err := scoped.WorkforceDomainService.ValidateProfile(ctx, profile); err != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, err
		}
		assignments, listErr := scoped.workforceRepository.ListIdentityWorkforceAssignments(ctx, scoped.WorkspaceID(), profile.ID)
		if listErr != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, listErr
		}
		for _, assignment := range assignments {
			if assignment.Status == identitymodel.IdentityStatusActive {
				mutation.EndAssignments = append(mutation.EndAssignments, identitymodel.IdentityWorkforceAssignmentEnd{AssignmentID: assignment.ID, EffectiveTo: strings.TrimSpace(request.EffectiveAt)})
			}
		}
		mutation.Profile = &profile
		mutation.RevokeEntitlements = true
	case IdentityWorkforceLifecycleRevokeAccess:
		profile, found, loadErr := scoped.workforceRepository.GetIdentityWorkforceProfile(ctx, scoped.WorkspaceID(), request.Profile.ID)
		if loadErr != nil {
			return identitymodel.IdentityWorkforceLifecycleResult{}, loadErr
		}
		if !found {
			return identitymodel.IdentityWorkforceLifecycleResult{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.workforce_profile_not_found"}
		}
		mutation.Profile = &profile
		mutation.RevokeEntitlements = true
	default:
		return identitymodel.IdentityWorkforceLifecycleResult{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.workforce_lifecycle_operation_invalid"}
	}
	return scoped.workforceLifecycle.ApplyIdentityWorkforceLifecycle(ctx, mutation)
}

func (s *IdentityApplicationService) RehireWorkforce(ctx context.Context, profileID, effectiveAt string, assignment identitymodel.IdentityWorkforceAssignment, actor identitymodel.Principal, reason string) (identitymodel.IdentityWorkforceLifecycleResult, error) {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return identitymodel.IdentityWorkforceLifecycleResult{}, err
	}
	if scoped.WorkforceDomainService == nil || scoped.workforceLifecycle == nil {
		return identitymodel.IdentityWorkforceLifecycleResult{}, &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_lifecycle_unavailable"}
	}
	if err := scoped.WorkforceDomainService.ValidateLifecycleEffectiveDate(effectiveAt); err != nil {
		return identitymodel.IdentityWorkforceLifecycleResult{}, err
	}
	profile, found, err := scoped.workforceRepository.GetIdentityWorkforceProfile(ctx, scoped.WorkspaceID(), strings.TrimSpace(profileID))
	if err != nil {
		return identitymodel.IdentityWorkforceLifecycleResult{}, err
	}
	if !found {
		return identitymodel.IdentityWorkforceLifecycleResult{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.workforce_profile_not_found"}
	}
	if profile.WorkStatus != identitymodel.IdentityWorkTerminated {
		return identitymodel.IdentityWorkforceLifecycleResult{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.workforce_rehire_requires_terminated"}
	}
	assignment.WorkforceProfileID = profile.ID
	assignment.AssignmentType = identitymodel.IdentityWorkforceAssignmentPrimary
	assignment.Status = identitymodel.IdentityStatusActive
	assignment.EffectiveFrom = strings.TrimSpace(effectiveAt)
	assignment.EffectiveTo = ""
	profile.WorkStatus = identitymodel.IdentityWorkActive
	profile.StartDate = strings.TrimSpace(effectiveAt)
	profile.EndDate = ""
	if err := scoped.WorkforceDomainService.ValidateAssignmentAgainstProfile(ctx, assignment, profile); err != nil {
		return identitymodel.IdentityWorkforceLifecycleResult{}, err
	}
	profile.PrimaryAssignmentID = assignment.ID
	return scoped.workforceLifecycle.ApplyIdentityWorkforceLifecycle(ctx, identitymodel.IdentityWorkforceLifecycleMutation{
		WorkspaceID: scoped.WorkspaceID(), ActorID: strings.TrimSpace(actor.UserID), Reason: strings.TrimSpace(reason),
		Profile: &profile, UpsertAssignments: []identitymodel.IdentityWorkforceAssignment{assignment},
	})
}
