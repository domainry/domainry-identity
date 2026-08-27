package identity

import (
	"context"
	"errors"
	"testing"

	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityApplicationBuildsGovernanceAndReferenceGraph(t *testing.T) {
	repository := &identityScopedRepository{
		departments: []identitymodel.IdentityDepartment{{ID: "department"}},
		users:       []identitymodel.IdentityUser{{ID: "user", Name: "User"}},
		roles: []identitymodel.IdentityRole{{
			ID: "role-id", Key: "role", Label: "Role",
		}},
		menus:       []identitymodel.IdentityMenu{{ID: "roles-menu", Key: "roles-menu", Label: "Roles", Route: "/admin/org/roles"}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "role-id"}},
		roleMenus:   []identitymodel.IdentityRoleMenuAssignment{{RoleID: "role-id", MenuID: "roles-menu"}},
	}
	service := NewIdentityApplicationService(repository, []identitymodel.IdentityPermissionDefinition{{Key: "order.read", Label: "Read orders", Resource: "order"}})
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "role", Name: "Role", Permissions: []string{"order.read"}, DataPermissions: []identitymodel.DataPermission{{ObjectKey: "order", Scope: "all_records", Read: true}}, FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "order", FieldKey: "amount", Read: true}}}})
	if _, err := service.ForWorkspace(" "); err == nil {
		t.Fatal("empty workspace accepted")
	}
	if scoped, err := service.ForWorkspace(" workspace-a "); err != nil || scoped == service {
		t.Fatalf("scoped=%p service=%p err=%v", scoped, service, err)
	}
	principal := identityGovernanceTestPrincipal()
	snapshot, err := service.GovernanceSnapshot(t.Context(), principal)
	if err != nil || len(snapshot.Users) != 1 || len(snapshot.Permissions) != 1 || len(snapshot.RoleMenuAssignments) != 1 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	input := changeplanmodel.ReferenceGraph{
		Nodes: []changeplanmodel.ReferenceNode{{ResourceType: "object", ResourceKey: "order"}},
	}
	graph, err := service.EnrichBusinessReferenceGraph(t.Context(), input, principal)
	if err != nil {
		t.Fatal(err)
	}
	wantNodes := map[string]bool{"permission": false, "menu": false, "role": false, "role_permission": false, "role_data_scope": false, "role_field_permission": false, "role_menu_assignment": false, "user": false}
	wantEdges := map[string]bool{"grants_permission": false, "governs_data_scope": false, "governs_field": false, "sees_menu": false, "assigned_role": false}
	for _, node := range graph.Nodes {
		if _, tracked := wantNodes[node.ResourceType]; tracked {
			wantNodes[node.ResourceType] = true
		}
	}
	for _, edge := range graph.Edges {
		if _, tracked := wantEdges[edge.Kind]; tracked {
			wantEdges[edge.Kind] = true
		}
	}
	for nodeType, found := range wantNodes {
		if !found {
			t.Errorf("missing node type %s in %#v", nodeType, graph.Nodes)
		}
	}
	for kind, found := range wantEdges {
		if !found {
			t.Errorf("missing edge kind %s in %#v", kind, graph.Edges)
		}
	}
}

func TestIdentityApplicationAuthorizationAndPrincipalConstructorEdges(t *testing.T) {
	service := NewIdentityApplicationService(&identityScopedRepository{}, nil)
	unknown := identitymodel.Principal{WorkspaceID: "workspace-a"}
	if _, err := service.GovernanceSnapshot(t.Context(), unknown); err == nil {
		t.Fatal("unknown principal accepted for governance snapshot")
	}
	if _, err := service.EnrichBusinessReferenceGraph(t.Context(), changeplanmodel.ReferenceGraph{}, unknown); err == nil {
		t.Fatal("unknown principal accepted for reference graph")
	}
	principalService := NewIdentityPrincipalApplicationService(IdentityPrincipalDependencies{
		Roles: func() []identitymodel.RoleSchema { return nil }, DefaultRoleKey: func() string { return "" },
	})
	if principalService == nil || principalService.IdentityPrincipalDomainService == nil {
		t.Fatalf("principal service=%#v", principalService)
	}
}

type identitySnapshotFaultSource struct {
	failAt string
}

func (s identitySnapshotFaultSource) failure(stage string) error {
	if s.failAt == stage {
		return errIdentitySeedTest
	}
	return nil
}

func (s identitySnapshotFaultSource) ListUsers(context.Context) ([]identitymodel.IdentityUser, error) {
	return nil, s.failure("users")
}

func (s identitySnapshotFaultSource) ListDepartments(context.Context) ([]identitymodel.IdentityDepartment, error) {
	return nil, s.failure("departments")
}

func (s identitySnapshotFaultSource) ListRoles(context.Context) ([]identitymodel.IdentityRole, error) {
	return nil, s.failure("roles")
}

func (identitySnapshotFaultSource) PublishedRoleDefinitions(context.Context) []identitymodel.RoleSchema {
	return nil
}

func (s identitySnapshotFaultSource) ListMenus(context.Context) ([]identitymodel.IdentityMenu, error) {
	return nil, s.failure("menus")
}

func (s identitySnapshotFaultSource) ListUserRoleAssignments(context.Context, string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return nil, s.failure("user_roles")
}

func (s identitySnapshotFaultSource) ListRoleMenuAssignments(context.Context, string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return nil, s.failure("role_menus")
}

func (identitySnapshotFaultSource) ListPermissions(context.Context) []identitymodel.IdentityPermissionDefinition {
	return nil
}

func TestBuildIdentityGovernanceSnapshotPropagatesEverySourceFailure(t *testing.T) {
	for _, stage := range []string{"users", "departments", "roles", "menus", "user_roles", "role_menus"} {
		t.Run(stage, func(t *testing.T) {
			_, err := BuildIdentityGovernanceSnapshot(t.Context(), identitySnapshotFaultSource{failAt: stage})
			if !errors.Is(err, errIdentitySeedTest) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

type identityReferenceRoleMenuFaultRepository struct {
	*identityScopedRepository
}

func (identityReferenceRoleMenuFaultRepository) ListIdentityRoleMenuAssignments(context.Context, string, string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return nil, errIdentitySeedTest
}

type identityReferenceUserRoleFaultRepository struct {
	*identityScopedRepository
}

type identityReferenceSecondCallFaultRepository struct {
	*identityScopedRepository
	roleMenuCalls int
	userRoleCalls int
}

func (r *identityReferenceSecondCallFaultRepository) ListIdentityRoleMenuAssignments(ctx context.Context, workspaceID, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	r.roleMenuCalls++
	if r.roleMenuCalls > 1 {
		return nil, errIdentitySeedTest
	}
	return r.identityScopedRepository.ListIdentityRoleMenuAssignments(ctx, workspaceID, roleID)
}

func (r *identityReferenceSecondCallFaultRepository) ListIdentityUserRoleAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	r.userRoleCalls++
	if r.userRoleCalls > 1 {
		return nil, errIdentitySeedTest
	}
	return r.identityScopedRepository.ListIdentityUserRoleAssignments(ctx, workspaceID, userID)
}

func (identityReferenceUserRoleFaultRepository) ListIdentityUserRoleAssignments(context.Context, string, string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return nil, errIdentitySeedTest
}

func TestIdentityReferenceGraphPropagatesAssignmentFailures(t *testing.T) {
	principal := identityGovernanceTestPrincipal()
	base := &identityScopedRepository{roles: []identitymodel.IdentityRole{{ID: "role", Key: "role"}}, users: []identitymodel.IdentityUser{{ID: "user"}}}
	roleService := NewIdentityApplicationService(identityReferenceRoleMenuFaultRepository{identityScopedRepository: base}, nil)
	if _, err := roleService.EnrichBusinessReferenceGraph(t.Context(), changeplanmodel.ReferenceGraph{}, principal); !errors.Is(err, errIdentitySeedTest) {
		t.Fatalf("role menu error = %v", err)
	}
	userOnly := &identityScopedRepository{users: []identitymodel.IdentityUser{{ID: "user"}}}
	userService := NewIdentityApplicationService(identityReferenceUserRoleFaultRepository{identityScopedRepository: userOnly}, nil)
	if _, err := userService.EnrichBusinessReferenceGraph(t.Context(), changeplanmodel.ReferenceGraph{}, principal); !errors.Is(err, errIdentitySeedTest) {
		t.Fatalf("user role error = %v", err)
	}
}

func TestIdentityReferenceGraphReusesSnapshotAssignmentsAndKeepsUnknownRoleID(t *testing.T) {
	base := &identityScopedRepository{
		roles:       []identitymodel.IdentityRole{{ID: "known-role", Key: "known"}},
		users:       []identitymodel.IdentityUser{{ID: "user"}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "unknown-role"}},
	}
	repository := &identityReferenceSecondCallFaultRepository{identityScopedRepository: base}
	service := NewIdentityApplicationService(repository, nil)
	graph, err := service.EnrichBusinessReferenceGraph(t.Context(), changeplanmodel.ReferenceGraph{}, identityGovernanceTestPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if repository.roleMenuCalls != 1 || repository.userRoleCalls != 1 {
		t.Fatalf("assignment reads role=%d user=%d", repository.roleMenuCalls, repository.userRoleCalls)
	}
	found := false
	for _, edge := range graph.Edges {
		if edge.Kind == "assigned_role" && edge.ToKey == "unknown-role" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unknown role id fallback missing: %#v", graph.Edges)
	}
}
