package identity

import (
	"context"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type WorkspaceIdentityProvisionStage string

const (
	WorkspaceIdentityProvisionStageUser           WorkspaceIdentityProvisionStage = "user"
	WorkspaceIdentityProvisionStageRole           WorkspaceIdentityProvisionStage = "role"
	WorkspaceIdentityProvisionStageRoleAssignment WorkspaceIdentityProvisionStage = "role_assignment"
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
	after func(WorkspaceIdentityProvisionStage) error,
) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if err := s.writeIdentityUser(ctx, execer, workspaceID, admin); err != nil {
		return fmt.Errorf("provision workspace administrator: %w", err)
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageUser); err != nil {
			return err
		}
	}
	if err := s.roleStore().UpsertBatchWithExecutor(ctx, execer, workspaceID, roles); err != nil {
		return fmt.Errorf("provision workspace roles: %w", err)
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageRole); err != nil {
			return err
		}
	}
	if err := s.writeIdentityUserRoleAssignment(ctx, execer, workspaceID, identitymodel.IdentityUserRoleAssignment{
		UserID: admin.ID, RoleID: workspaceRoleID(workspaceID, "admin"), Source: "workspace_provisioning", Status: "active",
	}); err != nil {
		return fmt.Errorf("assign workspace administrator role: %w", err)
	}
	if after != nil {
		if err := after(WorkspaceIdentityProvisionStageRoleAssignment); err != nil {
			return err
		}
	}
	return nil
}
