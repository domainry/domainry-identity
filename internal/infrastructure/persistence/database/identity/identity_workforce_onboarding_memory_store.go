package identity

import (
	"context"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) ApplyIdentityWorkforceOnboarding(_ context.Context, mutation identitymodel.IdentityWorkforceOnboardingMutation) (identitymodel.IdentityWorkforceOnboardingResult, error) {
	result := identitymodel.IdentityWorkforceOnboardingResult{
		User: mutation.User, Profile: mutation.Profile, Assignment: mutation.Assignment,
		RoleAssignments: append([]identitymodel.IdentityUserRoleAssignment(nil), mutation.RoleAssignments...),
	}
	prefix, err := identityWorkspacePrefix(mutation.WorkspaceID)
	if err != nil {
		return result, err
	}
	if mutation.User.ID == "" || mutation.Profile.ID == "" || mutation.Assignment.ID == "" {
		return result, fmt.Errorf("onboarding user, workforce profile, and assignment ids are required")
	}
	for _, assignment := range mutation.RoleAssignments {
		if assignment.UserID != mutation.User.ID || assignment.WorkforceProfileID != mutation.Profile.ID || assignment.RoleID == "" {
			return result, fmt.Errorf("onboarding role assignment boundary mismatch")
		}
	}
	if mutation.User.Status == "" {
		mutation.User.Status = identitymodel.IdentityStatusActive
		result.User.Status = mutation.User.Status
	}
	if mutation.Profile.Version == 0 {
		mutation.Profile.Version = 1
		result.Profile.Version = mutation.Profile.Version
	}
	if mutation.Assignment.Version == 0 {
		mutation.Assignment.Version = 1
		result.Assignment.Version = mutation.Assignment.Version
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, profile := range s.workforceProfiles {
		if key == prefix+mutation.Profile.ID || profile.OrganizationID != mutation.Profile.OrganizationID {
			continue
		}
		if profile.IdentityUserID == mutation.Profile.IdentityUserID || profile.WorkerNo == mutation.Profile.WorkerNo {
			return result, fmt.Errorf("workforce onboarding uniqueness conflict")
		}
	}
	s.users[prefix+mutation.User.ID] = cloneIdentityUser(mutation.User)
	s.workforceProfiles[prefix+mutation.Profile.ID] = mutation.Profile
	s.workforceAssignments[prefix+mutation.Assignment.ID] = mutation.Assignment
	for _, assignment := range mutation.RoleAssignments {
		s.userRoles[prefix+assignment.UserID+"\x00"+assignment.RoleID] = assignment
	}
	return result, nil
}
