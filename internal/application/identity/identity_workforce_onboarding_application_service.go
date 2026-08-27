package identity

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitydomain "github.com/domainry/domainry-identity/internal/domain/identity/service"
)

type IdentityWorkforceOnboardingRequest struct {
	User       identitymodel.IdentityUser                `json:"user"`
	Profile    identitymodel.IdentityWorkforceProfile    `json:"profile"`
	Assignment identitymodel.IdentityWorkforceAssignment `json:"assignment"`
	RoleIDs    []string                                  `json:"role_ids,omitempty"`
	ActorID    string                                    `json:"actor_id,omitempty"`
	Reason     string                                    `json:"reason,omitempty"`
}

func (s *IdentityApplicationService) OnboardWorkforce(ctx context.Context, request IdentityWorkforceOnboardingRequest, actor identitymodel.Principal) (identitymodel.IdentityWorkforceOnboardingResult, error) {
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return identitymodel.IdentityWorkforceOnboardingResult{}, err
	}
	if scoped.WorkforceDomainService == nil || scoped.workforceOnboarding == nil {
		return identitymodel.IdentityWorkforceOnboardingResult{}, apperror.New(apperror.KindUnavailable, "backend.identity.workforce_onboarding_unavailable", nil, nil)
	}
	request.ActorID = strings.TrimSpace(actor.UserID)
	request.Reason = strings.TrimSpace(request.Reason)
	user, roleAssignments, err := scoped.IdentityDomainService.PrepareWorkforceOnboarding(
		ctx, request.User, request.Profile.ID, request.RoleIDs, actor, request.Reason,
	)
	if err != nil {
		return identitymodel.IdentityWorkforceOnboardingResult{}, err
	}
	request.Profile.ID = strings.TrimSpace(request.Profile.ID)
	request.Profile.IdentityUserID = user.ID
	request.Profile.WorkStatus = identitymodel.IdentityWorkActive
	request.Assignment.ID = strings.TrimSpace(request.Assignment.ID)
	request.Assignment.WorkforceProfileID = request.Profile.ID
	request.Assignment.AssignmentType = identitymodel.IdentityWorkforceAssignmentPrimary
	request.Assignment.Status = identitymodel.IdentityStatusActive
	request.Profile.PrimaryAssignmentID = request.Assignment.ID
	if err := identitydomain.ValidateNewIdentityWorkforceProfile(request.Profile); err != nil {
		return identitymodel.IdentityWorkforceOnboardingResult{}, err
	}
	if err := scoped.WorkforceDomainService.ValidateAssignmentAgainstProfile(ctx, request.Assignment, request.Profile); err != nil {
		return identitymodel.IdentityWorkforceOnboardingResult{}, err
	}
	return scoped.workforceOnboarding.ApplyIdentityWorkforceOnboarding(ctx, identitymodel.IdentityWorkforceOnboardingMutation{
		WorkspaceID: scoped.WorkspaceID(), User: user, Profile: request.Profile, Assignment: request.Assignment,
		RoleAssignments: roleAssignments, ActorID: request.ActorID, Reason: request.Reason,
	})
}
