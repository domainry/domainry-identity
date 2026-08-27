package identity

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *IdentityApplicationService) ListRoles(ctx context.Context) ([]identitymodel.IdentityRole, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListRoles(ctx)
}

func (s *IdentityApplicationService) SearchRoles(ctx context.Context, query identitymodel.IdentityListQuery) (identitymodel.IdentityRolePage, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityRolePage{}, err
	}
	return scoped.SearchRoles(ctx, query)
}

func (s *IdentityApplicationService) ActiveRolesForUser(ctx context.Context, userID string) ([]identitymodel.IdentityRole, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ActiveRolesForUser(ctx, userID)
}

func (s *IdentityApplicationService) AssignUserRole(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	return scoped.AssignUserRole(ctx, assignment)
}

func (s *IdentityApplicationService) AssignUserRoleGoverned(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment, actor identitymodel.Principal) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	if !actor.Known || strings.TrimSpace(actor.UserID) == "" {
		return apperror.New(apperror.KindForbidden, "backend.identity.entitlement_actor_required", nil, nil)
	}
	role, found, err := scoped.RoleByID(ctx, assignment.RoleID)
	if err != nil {
		return err
	}
	if !found {
		return apperror.New(apperror.KindBadRequest, "backend.identity.role_not_found", nil, map[string]string{"role": assignment.RoleID})
	}
	definition, published := scoped.PublishedRoleDefinition(ctx, role.Key)
	if published {
		risk := definition.RiskLevel
		if risk == "" {
			risk = identitymodel.IdentityRoleRiskNormal
		}
		if risk == identitymodel.IdentityRoleRiskPrivileged && strings.TrimSpace(actor.UserID) == strings.TrimSpace(assignment.UserID) {
			return apperror.New(apperror.KindForbidden, "backend.identity.privileged_self_grant_denied", nil, nil)
		}
		if risk != identitymodel.IdentityRoleRiskNormal && !identityStringListContains(actor.Role.GrantableRoleKeys, "*") && !identityStringListContains(actor.Role.GrantableRoleKeys, definition.Key) {
			return apperror.New(apperror.KindForbidden, "backend.identity.role_grant_ceiling_exceeded", nil, nil)
		}
	}
	assignment.GrantedBy, assignment.Source = actor.UserID, "manual"
	return scoped.AssignUserRole(ctx, assignment)
}

func (s *IdentityApplicationService) UpsertUserWithRoles(ctx context.Context, user identitymodel.IdentityUser, assignments []identitymodel.IdentityUserRoleAssignment, actor identitymodel.Principal) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	return scoped.UpsertUserWithRoles(ctx, user, assignments, actor)
}

func identityStringListContains(values []string, expected string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(expected) {
			return true
		}
	}
	return false
}

func (s *IdentityApplicationService) RemoveUserRole(ctx context.Context, userID, roleID string) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	return scoped.RemoveUserRole(ctx, userID, roleID)
}

func (s *IdentityApplicationService) RemoveUserRoleGoverned(ctx context.Context, userID, roleID, reason string, actor identitymodel.Principal) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	return scoped.RemoveUserRoleGoverned(ctx, userID, roleID, actor.UserID, reason)
}

func (s *IdentityApplicationService) ListUserRoleAssignments(ctx context.Context, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListUserRoleAssignments(ctx, userID)
}

func (s *IdentityApplicationService) SearchUserRoleAssignments(ctx context.Context, userID string, query identitymodel.IdentityListQuery) (identitymodel.IdentityUserRoleAssignmentPage, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityUserRoleAssignmentPage{}, err
	}
	return scoped.SearchUserRoleAssignments(ctx, userID, query)
}

func (s *IdentityApplicationService) ListAssignableRoles(ctx context.Context, targetUserID string, actor identitymodel.Principal) ([]identitymodel.IdentityRole, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListAssignableRoles(ctx, targetUserID, actor)
}

func (s *IdentityApplicationService) ListAssignableWorkforceRoles(ctx context.Context, workforceProfileID string, actor identitymodel.Principal) ([]identitymodel.IdentityRole, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListAssignableWorkforceRoles(ctx, workforceProfileID, actor)
}

func (s *IdentityApplicationService) ListRequestableRoles(ctx context.Context) ([]identitymodel.IdentityRole, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListRequestableRoles(ctx)
}

func (s *IdentityApplicationService) CreateRoleRequest(ctx context.Context, request identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	return scoped.CreateRoleRequest(ctx, request)
}

func (s *IdentityApplicationService) ListRoleRequests(ctx context.Context, status, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListRoleRequests(ctx, status, userID)
}

func (s *IdentityApplicationService) ApproveRoleRequest(ctx context.Context, requestID, reviewerID, note string, reviewer ...identitymodel.Principal) (identitymodel.IdentityRoleRequest, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	return scoped.ApproveRoleRequest(ctx, requestID, reviewerID, note, reviewer...)
}

func (s *IdentityApplicationService) RejectRoleRequest(ctx context.Context, requestID, reviewerID, note string) (identitymodel.IdentityRoleRequest, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	return scoped.RejectRoleRequest(ctx, requestID, reviewerID, note)
}

func (s *IdentityApplicationService) RoleByID(ctx context.Context, roleID string) (identitymodel.IdentityRole, bool, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityRole{}, false, err
	}
	return scoped.RoleByID(ctx, roleID)
}

func (s *IdentityApplicationService) ListRolePermissionAssignments(ctx context.Context, roleID string) ([]identitymodel.IdentityRolePermissionAssignment, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListRolePermissionAssignments(ctx, roleID)
}

func (s *IdentityApplicationService) ListRoleDataScopes(ctx context.Context, roleID string) ([]identitymodel.IdentityDataScopePolicy, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListRoleDataScopes(ctx, roleID)
}

func (s *IdentityApplicationService) ListRoleFieldPermissions(ctx context.Context, roleID string) ([]identitymodel.IdentityFieldPermission, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListRoleFieldPermissions(ctx, roleID)
}

func (s *IdentityApplicationService) UpsertMenu(ctx context.Context, menu identitymodel.IdentityMenu) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	return scoped.UpsertMenu(ctx, menu)
}

func (s *IdentityApplicationService) RemoveMenu(ctx context.Context, menuID string) ([]string, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.RemoveMenu(ctx, menuID)
}

func (s *IdentityApplicationService) SetRoleMenus(ctx context.Context, roleID string, menuIDs []string) error {
	if err := s.ValidateRoleMenus(ctx, roleID, menuIDs); err != nil {
		return err
	}
	// Validation resolved the same immutable workspace context successfully.
	scoped, _ := s.domainForContext(ctx)
	return scoped.SetRoleMenus(ctx, roleID, menuIDs)
}

func (s *IdentityApplicationService) ValidateRoleMenus(ctx context.Context, roleID string, menuIDs []string) error {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return err
	}
	role, found, err := scoped.RoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if !found {
		return apperror.New(apperror.KindBadRequest, "backend.identity.role_not_found", nil, map[string]string{"role": roleID})
	}
	definition, published := scoped.PublishedRoleDefinition(ctx, role.Key)
	if !published {
		return apperror.New(apperror.KindBadRequest, "backend.identity.role_definition_not_published", nil, map[string]string{"role": role.Key})
	}
	menus, err := scoped.ListMenus(ctx)
	if err != nil {
		return err
	}
	menusByID := make(map[string]identitymodel.IdentityMenu, len(menus)*2)
	for _, menu := range menus {
		menusByID[menu.ID] = menu
		menusByID[menu.Key] = menu
	}
	seen := make(map[string]bool, len(menuIDs))
	for _, menuID := range menuIDs {
		menuID = strings.TrimSpace(menuID)
		if menuID == "" {
			continue
		}
		if seen[menuID] {
			return apperror.New(apperror.KindBadRequest, "backend.identity.menu_assignment_duplicate", nil, map[string]string{"menu": menuID})
		}
		seen[menuID] = true
		menu, exists := menusByID[menuID]
		if !exists || menu.Status == identitymodel.IdentityStatusDisabled || menu.Status == identitymodel.IdentityStatusDeleted {
			return apperror.New(apperror.KindBadRequest, "backend.identity.menu_not_active", nil, map[string]string{"menu": menuID})
		}
		if menu.Route == "" {
			continue
		}
		required, registered := requiredPermissionsForMenuRoute(menu.Route)
		if !registered {
			return apperror.New(apperror.KindBadRequest, "backend.identity.menu_route_not_registered", nil, map[string]string{"menu": menu.ID, "route": menu.Route})
		}
		for _, permission := range required {
			if !identityStringListContains(definition.Permissions, permission) {
				return apperror.New(apperror.KindBadRequest, "backend.identity.menu_route_permission_missing", nil, map[string]string{"menu": menu.ID, "route": menu.Route, "permission": permission})
			}
		}
	}
	return nil
}

func (s *IdentityApplicationService) ListRoleMenuAssignments(ctx context.Context, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListRoleMenuAssignments(ctx, roleID)
}
