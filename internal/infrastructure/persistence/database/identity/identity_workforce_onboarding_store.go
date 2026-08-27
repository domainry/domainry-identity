package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *SQLIdentityStore) ApplyIdentityWorkforceOnboarding(ctx context.Context, mutation identitymodel.IdentityWorkforceOnboardingMutation) (identitymodel.IdentityWorkforceOnboardingResult, error) {
	result := identitymodel.IdentityWorkforceOnboardingResult{
		User: mutation.User, Profile: mutation.Profile, Assignment: mutation.Assignment,
		RoleAssignments: append([]identitymodel.IdentityUserRoleAssignment(nil), mutation.RoleAssignments...),
	}
	workspaceID, err := identityWorkspaceID(mutation.WorkspaceID)
	if err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if err := s.writeIdentityUser(ctx, tx, workspaceID, mutation.User); err != nil {
		return result, err
	}
	if err := s.writeIdentityWorkforceProfile(ctx, tx, workspaceID, mutation.Profile); err != nil {
		return result, err
	}
	if err := s.writeIdentityWorkforceAssignment(ctx, tx, workspaceID, mutation.Assignment); err != nil {
		return result, err
	}
	for _, assignment := range mutation.RoleAssignments {
		if err := s.writeIdentityUserRoleAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return result, err
		}
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}
