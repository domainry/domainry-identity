package identity

import (
	"context"
	"sort"

	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type IdentityGovernanceSnapshotSource interface {
	ListUsers(context.Context) ([]identitymodel.IdentityUser, error)
	ListDepartments(context.Context) ([]identitymodel.IdentityDepartment, error)
	ListRoles(context.Context) ([]identitymodel.IdentityRole, error)
	PublishedRoleDefinitions(context.Context) []identitymodel.RoleSchema
	ListMenus(context.Context) ([]identitymodel.IdentityMenu, error)
	ListUserRoleAssignments(context.Context, string) ([]identitymodel.IdentityUserRoleAssignment, error)
	ListRoleMenuAssignments(context.Context, string) ([]identitymodel.IdentityRoleMenuAssignment, error)
	ListPermissions(context.Context) []identitymodel.IdentityPermissionDefinition
}

func BuildIdentityGovernanceSnapshot(ctx context.Context, source IdentityGovernanceSnapshotSource) (changeplanmodel.IdentityGovernance, error) {
	users, err := source.ListUsers(ctx)
	if err != nil {
		return changeplanmodel.IdentityGovernance{}, err
	}
	departments, err := source.ListDepartments(ctx)
	if err != nil {
		return changeplanmodel.IdentityGovernance{}, err
	}
	roles, err := source.ListRoles(ctx)
	if err != nil {
		return changeplanmodel.IdentityGovernance{}, err
	}
	menus, err := source.ListMenus(ctx)
	if err != nil {
		return changeplanmodel.IdentityGovernance{}, err
	}
	userRoles, err := source.ListUserRoleAssignments(ctx, "")
	if err != nil {
		return changeplanmodel.IdentityGovernance{}, err
	}
	roleMenus, err := source.ListRoleMenuAssignments(ctx, "")
	if err != nil {
		return changeplanmodel.IdentityGovernance{}, err
	}
	snapshot := changeplanmodel.IdentityGovernance{Users: users, Departments: departments, Roles: roles, RoleDefinitions: source.PublishedRoleDefinitions(ctx), Permissions: source.ListPermissions(ctx), Menus: menus, UserRoleAssignments: userRoles, RoleMenuAssignments: roleMenus}
	NormalizeIdentityGovernanceSnapshot(&snapshot)
	return snapshot, nil
}

func NormalizeIdentityGovernanceSnapshot(snapshot *changeplanmodel.IdentityGovernance) {
	if snapshot.Users == nil {
		snapshot.Users = []identitymodel.IdentityUser{}
	}
	if snapshot.Departments == nil {
		snapshot.Departments = []identitymodel.IdentityDepartment{}
	}
	if snapshot.Roles == nil {
		snapshot.Roles = []identitymodel.IdentityRole{}
	}
	if snapshot.RoleDefinitions == nil {
		snapshot.RoleDefinitions = []identitymodel.RoleSchema{}
	}
	if snapshot.Permissions == nil {
		snapshot.Permissions = []identitymodel.IdentityPermissionDefinition{}
	}
	if snapshot.Menus == nil {
		snapshot.Menus = []identitymodel.IdentityMenu{}
	}
	if snapshot.UserRoleAssignments == nil {
		snapshot.UserRoleAssignments = []identitymodel.IdentityUserRoleAssignment{}
	}
	if snapshot.RoleMenuAssignments == nil {
		snapshot.RoleMenuAssignments = []identitymodel.IdentityRoleMenuAssignment{}
	}
	sort.Slice(snapshot.Users, func(i, j int) bool { return snapshot.Users[i].ID < snapshot.Users[j].ID })
	sort.Slice(snapshot.Departments, func(i, j int) bool { return snapshot.Departments[i].ID < snapshot.Departments[j].ID })
	sort.Slice(snapshot.Roles, func(i, j int) bool { return snapshot.Roles[i].ID < snapshot.Roles[j].ID })
	sort.Slice(snapshot.RoleDefinitions, func(i, j int) bool { return snapshot.RoleDefinitions[i].Key < snapshot.RoleDefinitions[j].Key })
	sort.Slice(snapshot.Permissions, func(i, j int) bool { return snapshot.Permissions[i].Key < snapshot.Permissions[j].Key })
	sort.Slice(snapshot.Menus, func(i, j int) bool { return snapshot.Menus[i].Key < snapshot.Menus[j].Key })
	sort.Slice(snapshot.UserRoleAssignments, func(i, j int) bool {
		return snapshot.UserRoleAssignments[i].UserID+"\x00"+snapshot.UserRoleAssignments[i].RoleID < snapshot.UserRoleAssignments[j].UserID+"\x00"+snapshot.UserRoleAssignments[j].RoleID
	})
	sort.Slice(snapshot.RoleMenuAssignments, func(i, j int) bool {
		return snapshot.RoleMenuAssignments[i].RoleID+"\x00"+snapshot.RoleMenuAssignments[i].MenuID < snapshot.RoleMenuAssignments[j].RoleID+"\x00"+snapshot.RoleMenuAssignments[j].MenuID
	})
}
