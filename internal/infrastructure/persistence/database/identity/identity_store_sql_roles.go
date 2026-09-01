package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	rolepersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/authorization/role"
	rolerequestpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/authorization/rolerequest"
	roleassignmentpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/roleassignment"
)

func (s *SQLIdentityStore) roleStore() *rolepersistence.Store {
	return rolepersistence.New(s, nowString)
}

func (s *SQLIdentityStore) roleRequestStore() *rolerequestpersistence.Store {
	return rolerequestpersistence.New(s, nowString, func(ctx context.Context, execer rolerequestpersistence.Execer, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
		return s.writeIdentityUserRoleAssignment(ctx, execer, workspaceID, assignment)
	})
}

func (s *SQLIdentityStore) ListIdentityRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	return s.loadRoles(ctx, workspaceID)
}

func (s *SQLIdentityStore) UpsertIdentityRole(ctx context.Context, workspaceID string, role identitymodel.IdentityRole) error {
	return s.roleStore().Upsert(ctx, workspaceID, role)
}

func (s *SQLIdentityStore) UpsertIdentityRoleWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID string, role identitymodel.IdentityRole) error {
	return s.roleStore().UpsertWithExecutor(ctx, execer, workspaceID, role)
}

func (s *SQLIdentityStore) UpsertIdentityRolesWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID string, roles []identitymodel.IdentityRole) error {
	return s.roleStore().UpsertBatchWithExecutor(ctx, execer, workspaceID, roles)
}

func (s *SQLIdentityStore) RemoveIdentityRole(ctx context.Context, workspaceID, roleID string) error {
	return s.roleStore().Remove(ctx, workspaceID, roleID)
}

func (s *SQLIdentityStore) AssignIdentityUserRole(ctx context.Context, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
	return s.writeIdentityUserRoleAssignment(ctx, s.db, workspaceID, assignment)
}

func (s *SQLIdentityStore) writeIdentityUserRoleAssignment(ctx context.Context, execer identityUserExecer, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
	return roleassignmentpersistence.New(s, nowString).Upsert(ctx, execer, workspaceID, assignment)
}

func (s *SQLIdentityStore) RemoveIdentityUserRole(ctx context.Context, workspaceID, userID, roleID string) error {
	return s.roleStore().RemoveUserAssignment(ctx, workspaceID, userID, roleID)
}

func (s *SQLIdentityStore) ListIdentityUserRoleAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return s.loadUserRoleAssignments(ctx, workspaceID, userID)
}

func (s *SQLIdentityStore) CreateIdentityRoleRequest(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error) {
	return s.roleRequestStore().Create(ctx, workspaceID, request)
}

func (s *SQLIdentityStore) ListIdentityRoleRequests(ctx context.Context, workspaceID, status, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	return s.loadRoleRequests(ctx, workspaceID, status, userID)
}

func (s *SQLIdentityStore) UpdateIdentityRoleRequest(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest) error {
	return s.roleRequestStore().Update(ctx, workspaceID, request)
}

func (s *SQLIdentityStore) ApplyIdentityRoleRequestDecision(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, expectedStatus string) error {
	return s.roleRequestStore().ApplyDecision(ctx, workspaceID, request, assignments, expectedStatus)
}

func (s *SQLIdentityStore) loadRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	return s.roleStore().List(ctx, workspaceID)
}

func (s *SQLIdentityStore) loadUserRoleAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return s.roleStore().ListUserAssignments(ctx, workspaceID, userID)
}

func (s *SQLIdentityStore) loadRoleRequests(ctx context.Context, workspaceID, status, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	return s.roleRequestStore().List(ctx, workspaceID, status, userID)
}

func (s *SQLIdentityStore) memoryRole(ctx context.Context, workspaceID, roleID string) (identitymodel.IdentityRole, bool, error) {
	roles, err := s.ListIdentityRoles(ctx, workspaceID)
	if err != nil {
		return identitymodel.IdentityRole{}, false, err
	}
	for _, role := range roles {
		if role.ID == roleID {
			return role, true, nil
		}
	}
	return identitymodel.IdentityRole{}, false, nil
}
