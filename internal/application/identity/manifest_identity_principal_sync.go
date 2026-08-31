package identity

import (
	"context"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func syncManifestIdentityRoles(ctx context.Context, identityStore identityrepository.IdentitySeedRepository, desired []identitymodel.IdentityRole) error {
	workspaceID := manifestIdentityWorkspaceID(ctx)
	existing, err := identityStore.ListIdentityRoles(ctx, workspaceID)
	if err != nil {
		return err
	}
	existingIDs := map[string]bool{}
	for _, role := range existing {
		existingIDs[role.ID] = true
	}
	for _, role := range desired {
		if strings.TrimSpace(role.ID) == "" || existingIDs[role.ID] {
			continue
		}
		if role.Status == "" {
			role.Status = identitymodel.IdentityStatusActive
		}
		if err := identityStore.UpsertIdentityRole(ctx, workspaceID, role); err != nil {
			return fmt.Errorf("sync identity role %s: %w", role.ID, err)
		}
	}
	return nil
}

func syncManifestIdentityUsers(ctx context.Context, identityStore identityrepository.IdentitySeedRepository, desiredUsers []identitymodel.IdentityUser, desiredUserRoles []identitymodel.IdentityUserRoleAssignment) error {
	workspaceID := manifestIdentityWorkspaceID(ctx)
	if _, err := identitymodel.NewWorkspaceID(workspaceID); err != nil {
		return fmt.Errorf("sync manifest identity users requires initialized workspace: %w", err)
	}
	for _, user := range desiredUsers {
		if strings.TrimSpace(user.ID) == "" {
			continue
		}
		if user.Status == "" {
			user.Status = identitymodel.IdentityStatusActive
		}
		if err := identityStore.UpsertIdentityUser(ctx, workspaceID, user); err != nil {
			return fmt.Errorf("sync identity user %s: %w", user.ID, err)
		}
	}
	for _, assignment := range desiredUserRoles {
		if strings.TrimSpace(assignment.UserID) == "" || strings.TrimSpace(assignment.RoleID) == "" {
			continue
		}
		if err := identityStore.AssignIdentityUserRole(ctx, workspaceID, assignment); err != nil {
			return fmt.Errorf("sync identity user role %s/%s: %w", assignment.UserID, assignment.RoleID, err)
		}
	}
	return nil
}
