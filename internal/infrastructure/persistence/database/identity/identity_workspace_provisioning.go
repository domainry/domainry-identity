package identity

import (
	"context"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// ProvisionWorkspaceIdentityWithExecutor persists only Identity-owned state
// through a host-owned transaction. It deliberately does not commit or roll
// back that transaction.
func (s *SQLIdentityStore) ProvisionWorkspaceIdentityWithExecutor(
	ctx context.Context,
	execer identityUserExecer,
	workspaceID string,
	admin identitymodel.IdentityUser,
	roles []identitymodel.IdentityRole,
) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if err := s.writeIdentityUser(ctx, execer, workspaceID, admin); err != nil {
		return fmt.Errorf("provision workspace administrator: %w", err)
	}
	for _, role := range roles {
		if err := s.roleStore().UpsertWithExecutor(ctx, execer, workspaceID, role); err != nil {
			return fmt.Errorf("provision workspace role %s: %w", role.Key, err)
		}
	}
	if err := s.writeIdentityUserRoleAssignment(ctx, execer, workspaceID, identitymodel.IdentityUserRoleAssignment{
		UserID: admin.ID, RoleID: workspaceRoleID(workspaceID, "admin"), Source: "workspace_provisioning", Status: "active",
	}); err != nil {
		return fmt.Errorf("assign workspace administrator role: %w", err)
	}
	return nil
}
