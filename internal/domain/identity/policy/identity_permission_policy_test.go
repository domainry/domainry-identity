package policy

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityRolePermissionPolicy(t *testing.T) {
	role := identitymodel.RoleSchema{Permissions: []string{"invoice.read", "ops.workflow.*"}}
	if !IdentityRoleHasPermissionKey(role, "invoice.read") {
		t.Fatal("expected exact permission")
	}
	if !IdentityRoleHasPermissionKey(role, "ops.workflow.publish") {
		t.Fatal("expected wildcard permission")
	}
	if IdentityRoleHasPermissionKey(role, "invoice.update") {
		t.Fatal("unexpected update permission")
	}
	if !IdentityRoleAllows(role, "invoice", "view") {
		t.Fatal("expected view alias to resolve to read")
	}
}

func TestIdentityRoleDataPermissionPolicy(t *testing.T) {
	role := identitymodel.RoleSchema{DataPermissions: []identitymodel.DataPermission{{ObjectKey: "invoice", Read: true, Scope: "department"}}}
	if !IdentityRoleAllowsData(role, "invoice", "read") || IdentityRoleAllowsData(role, "invoice", "update") {
		t.Fatal("unexpected data permission decision")
	}
	if scope := IdentityDataScopeForAction(role, "invoice", "read"); scope != "department" {
		t.Fatalf("scope=%q", scope)
	}
	if scope := IdentityDataScope(role, "invoice", false); scope != "department" {
		t.Fatalf("read scope=%q", scope)
	}
	if scope := IdentityDataScope(role, "invoice", true); scope != "none" {
		t.Fatalf("write scope=%q", scope)
	}
	if scope := IdentityDataScope(role, "missing", false); scope != "none" {
		t.Fatalf("missing scope=%q", scope)
	}
}

func TestWorkspaceAdministratorDataPolicyCoversDynamicallyPublishedObjects(t *testing.T) {
	role := identitymodel.RoleSchema{
		Permissions: []string{"workspace.admin"}, RecordScope: "all_records",
		DataPermissions: []identitymodel.DataPermission{{ObjectKey: "runtime_owned_job", Scope: "all_records", Read: true, Write: true}},
	}
	if !IdentityRoleAllowsData(role, "new_business_object", "read") || !IdentityRoleAllowsData(role, "new_business_object", "update") {
		t.Fatal("workspace administrator must retain data authority for dynamically published objects")
	}
	if scope := IdentityDataScope(role, "new_business_object", true); scope != "all_records" {
		t.Fatalf("workspace administrator dynamic object scope=%q", scope)
	}
}
