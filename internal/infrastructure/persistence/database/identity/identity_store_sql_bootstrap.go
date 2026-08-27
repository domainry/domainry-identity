package identity

import (
	"context"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// ApplyIdentityBootstrapAtomically keeps the platform Identity graph from
// becoming partially visible when a department, user, or assignment fails.
// Roles are synchronized before this boundary because assignments reference
// the manifest-owned role definitions.
func (s *SQLIdentityStore) ApplyIdentityBootstrapAtomically(
	ctx context.Context,
	workspaceID string,
	departments []identitymodel.IdentityDepartment,
	users []identitymodel.IdentityUser,
	workforceProfiles []identitymodel.IdentityWorkforceProfile,
	workforceAssignments []identitymodel.IdentityWorkforceAssignment,
	roleAssignments []identitymodel.IdentityUserRoleAssignment,
) error {
	if _, err := identityWorkspaceID(workspaceID); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		_ = tx.Rollback()
		return cause
	}
	for _, department := range departments {
		if err := s.writeIdentityDepartment(ctx, tx, workspaceID, department); err != nil {
			return rollback(fmt.Errorf("write bootstrap department %s: %w", department.ID, err))
		}
	}
	for _, user := range users {
		if err := s.writeIdentityUser(ctx, tx, workspaceID, user); err != nil {
			return rollback(fmt.Errorf("write bootstrap user %s: %w", user.ID, err))
		}
	}
	for _, profile := range workforceProfiles {
		if err := s.writeIdentityWorkforceProfile(ctx, tx, workspaceID, profile); err != nil {
			return rollback(fmt.Errorf("write bootstrap workforce profile %s: %w", profile.ID, err))
		}
	}
	for _, assignment := range workforceAssignments {
		if err := s.writeIdentityWorkforceAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return rollback(fmt.Errorf("write bootstrap workforce assignment %s: %w", assignment.ID, err))
		}
	}
	for _, assignment := range roleAssignments {
		if err := s.writeIdentityUserRoleAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return rollback(fmt.Errorf("write bootstrap user role %s/%s: %w", assignment.UserID, assignment.RoleID, err))
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}
