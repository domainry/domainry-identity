package identity

import (
	"context"
	"testing"

	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type snapshotSource struct{}

func (snapshotSource) ListUsers(context.Context) ([]identitymodel.IdentityUser, error) {
	return []identitymodel.IdentityUser{{ID: "user-b"}, {ID: "user-a"}}, nil
}
func (snapshotSource) ListDepartments(context.Context) ([]identitymodel.IdentityDepartment, error) {
	return []identitymodel.IdentityDepartment{{ID: "department-b"}, {ID: "department-a"}}, nil
}
func (snapshotSource) ListRoles(context.Context) ([]identitymodel.IdentityRole, error) {
	return []identitymodel.IdentityRole{{ID: "role-b"}, {ID: "role-a"}}, nil
}
func (snapshotSource) PublishedRoleDefinitions(context.Context) []identitymodel.RoleSchema {
	return []identitymodel.RoleSchema{{Key: "role-b"}, {Key: "role-a"}}
}
func (snapshotSource) ListMenus(context.Context) ([]identitymodel.IdentityMenu, error) {
	return []identitymodel.IdentityMenu{{Key: "menu-b"}, {Key: "menu-a"}}, nil
}
func (snapshotSource) ListUserRoleAssignments(context.Context, string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return []identitymodel.IdentityUserRoleAssignment{{UserID: "user-b", RoleID: "role-a"}, {UserID: "user-a", RoleID: "role-b"}}, nil
}
func (snapshotSource) ListRoleMenuAssignments(context.Context, string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return []identitymodel.IdentityRoleMenuAssignment{{RoleID: "role-b", MenuID: "menu-a"}, {RoleID: "role-a", MenuID: "menu-b"}}, nil
}
func (snapshotSource) ListPermissions(context.Context) []identitymodel.IdentityPermissionDefinition {
	return []identitymodel.IdentityPermissionDefinition{{Key: "permission-b"}, {Key: "permission-a"}}
}

func TestBuildIdentityGovernanceSnapshotPreservesFactsAndNormalizesOrder(t *testing.T) {
	snapshot, err := BuildIdentityGovernanceSnapshot(t.Context(), snapshotSource{})
	if err != nil {
		t.Fatalf("build governance snapshot: %v", err)
	}
	NormalizeIdentityGovernanceSnapshot(&snapshot)
	if snapshot.Users[0].ID != "user-a" || snapshot.Departments[0].ID != "department-a" || snapshot.Roles[0].ID != "role-a" || snapshot.RoleDefinitions[0].Key != "role-a" {
		t.Fatalf("identity facts not normalized: %#v", snapshot)
	}
	if snapshot.Permissions[0].Key != "permission-a" || snapshot.Menus[0].Key != "menu-a" {
		t.Fatalf("governance catalog not normalized: %#v", snapshot)
	}
	if len(snapshot.UserRoleAssignments) != 2 || len(snapshot.RoleMenuAssignments) != 2 {
		t.Fatalf("assignment facts lost: %#v", snapshot)
	}
}

func TestIdentityGovernanceSnapshotNormalizeUsesEmptyCollections(t *testing.T) {
	snapshot := changeplanmodel.IdentityGovernance{}
	NormalizeIdentityGovernanceSnapshot(&snapshot)
	if snapshot.Users == nil || snapshot.Departments == nil || snapshot.Roles == nil || snapshot.RoleDefinitions == nil || snapshot.Permissions == nil || snapshot.Menus == nil || snapshot.UserRoleAssignments == nil || snapshot.RoleMenuAssignments == nil {
		t.Fatalf("expected JSON-stable empty collections: %#v", snapshot)
	}
}
