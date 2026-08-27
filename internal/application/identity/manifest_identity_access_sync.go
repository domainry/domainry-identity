package identity

import (
	"context"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func syncManifestIdentityMenus(ctx context.Context, identityStore identityrepository.IdentitySeedRepository, desired []identitymodel.IdentityMenu) error {
	workspaceID := manifestIdentityWorkspaceID(ctx)
	for _, menu := range desired {
		if strings.TrimSpace(menu.ID) == "" {
			continue
		}
		if menu.Status == "" {
			menu.Status = identitymodel.IdentityStatusActive
		}
		if err := identityStore.UpsertIdentityMenu(ctx, workspaceID, menu); err != nil {
			return fmt.Errorf("sync identity menu %s: %w", menu.ID, err)
		}
	}
	return nil
}

func syncManifestIdentityRoleMenus(ctx context.Context, identityStore identityrepository.IdentitySeedRepository, desiredRoles []identitymodel.IdentityRole, desiredRoleMenus []identitymodel.IdentityRoleMenuAssignment) error {
	workspaceID := manifestIdentityWorkspaceID(ctx)
	menuIDsByRole := map[string][]string{}
	for _, assignment := range desiredRoleMenus {
		if strings.TrimSpace(assignment.RoleID) == "" || strings.TrimSpace(assignment.MenuID) == "" {
			continue
		}
		menuIDsByRole[assignment.RoleID] = append(menuIDsByRole[assignment.RoleID], assignment.MenuID)
	}
	for _, role := range desiredRoles {
		if strings.TrimSpace(role.ID) == "" {
			continue
		}
		menuSet := map[string]bool{}
		for _, menuID := range menuIDsByRole[role.ID] {
			menuSet[menuID] = true
		}
		if err := identityStore.SetIdentityRoleMenus(ctx, workspaceID, role.ID, sortedKeys(menuSet)); err != nil {
			return fmt.Errorf("sync identity role menus %s: %w", role.ID, err)
		}
	}
	return nil
}

func syncManifestIdentityMenuRetirements(ctx context.Context, identityStore identityrepository.IdentitySeedRepository, desired []identitymodel.IdentityMenu) error {
	workspaceID := manifestIdentityWorkspaceID(ctx)
	desiredIDs := map[string]bool{}
	desiredRoutes := map[string]bool{}
	for _, menu := range desired {
		if id := strings.TrimSpace(menu.ID); id != "" {
			desiredIDs[id] = true
		}
		if route := strings.TrimSpace(menu.Route); route != "" {
			desiredRoutes[route] = true
		}
	}
	assignments, err := identityStore.ListIdentityRoleMenuAssignments(ctx, workspaceID, "")
	if err != nil {
		return err
	}
	assigned := map[string]bool{}
	for _, assignment := range assignments {
		if menuID := strings.TrimSpace(assignment.MenuID); menuID != "" {
			assigned[menuID] = true
		}
	}
	menus, err := identityStore.ListIdentityMenus(ctx, workspaceID)
	if err != nil {
		return err
	}
	for _, menu := range menus {
		if desiredIDs[menu.ID] || assigned[menu.ID] || menu.Status != identitymodel.IdentityStatusActive || !desiredRoutes[strings.TrimSpace(menu.Route)] {
			continue
		}
		menu.Status = identitymodel.IdentityStatusDisabled
		if err := identityStore.UpsertIdentityMenu(ctx, workspaceID, menu); err != nil {
			return fmt.Errorf("retire identity menu %s: %w", menu.ID, err)
		}
	}
	return nil
}

func cloneContextualFieldPolicies(values []identitymodel.ContextualFieldPolicyRule) []identitymodel.ContextualFieldPolicyRule {
	out := append([]identitymodel.ContextualFieldPolicyRule(nil), values...)
	for index := range out {
		out[index].Actions = append([]string(nil), values[index].Actions...)
		out[index].Predicate = cloneIdentityPolicyExpression(values[index].Predicate)
		if values[index].MaskStrategy != nil {
			mask := *values[index].MaskStrategy
			out[index].MaskStrategy = &mask
		}
	}
	return out
}

func cloneIdentityPolicyExpression(value *identitymodel.IdentityPolicyExpression) *identitymodel.IdentityPolicyExpression {
	if value == nil {
		return nil
	}
	out := *value
	out.Path = append([]identitymodel.IdentityPolicyRelationSegment(nil), value.Path...)
	out.Values = append([]string(nil), value.Values...)
	out.Children = make([]identitymodel.IdentityPolicyExpression, len(value.Children))
	for index := range value.Children {
		out.Children[index] = *cloneIdentityPolicyExpression(&value.Children[index])
	}
	return &out
}
