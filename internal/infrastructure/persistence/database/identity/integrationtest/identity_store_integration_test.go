// Identity store and domain integration tests.
package identity_test

import (
	identitypolicy "github.com/domainry/domainry-identity/internal/domain/identity/policy"
	"strings"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	identitybusiness "github.com/domainry/domainry-identity/internal/domain/identity/service"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestIdentityServiceValidatesPermissionsAndComputesEffectiveKeys(t *testing.T) {
	repo := identitypersistence.NewMemoryIdentityStore()
	service, _ := identitybusiness.NewIdentityDomainService(repo, []identitymodel.IdentityPermissionDefinition{
		{Key: "crm.customer.view", System: "crm", Resource: "customer", Action: "view"},
		{Key: "crm.customer.edit", System: "crm", Resource: "customer", Action: "edit"},
	}).ForWorkspace(identitymodel.InstallationWorkspaceID)
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "company", Name: "Company", Path: "/company"}); err != nil {
		t.Fatalf("upsert company department: %v", err)
	}
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{ID: "u-admin", Name: "Admin", Email: "admin@example.com"}); err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	seedIdentityDirectoryRole(t, repo, identitymodel.InstallationWorkspaceID, identitymodel.IdentityRole{ID: "r-admin", Key: "admin", Label: "Admin"})
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "u-admin", RoleID: "r-admin"}); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "d-root", Name: "Root", Path: "/root"}); err != nil {
		t.Fatalf("upsert root department: %v", err)
	}
	rootParent := "d-root"
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "d-child", Name: "Child", ParentID: &rootParent, Path: "/root/child"}); err != nil {
		t.Fatalf("upsert child department: %v", err)
	}
	childParent := "d-child"
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "d-grandchild", Name: "Grandchild", ParentID: &childParent, Path: "/root/child/grandchild"}); err != nil {
		t.Fatalf("upsert grandchild department: %v", err)
	}
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "d-child", Name: "Child", ParentID: &rootParent, Path: "/root/revenue/child"}); err != nil {
		t.Fatalf("move child department: %v", err)
	}
	movedDepartments, err := service.ListDepartments(t.Context())
	if err != nil {
		t.Fatalf("list moved departments: %v", err)
	}
	movedDepartmentPaths := map[string]string{}
	for _, department := range movedDepartments {
		movedDepartmentPaths[department.ID] = department.Path
	}
	if movedDepartmentPaths["d-grandchild"] != "/root/revenue/child/grandchild" {
		t.Fatalf("expected child department path to be rebuilt, got %#v", movedDepartmentPaths)
	}
	selfParent := "d-self"
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "d-self", Name: "Self", ParentID: &selfParent, Path: "/self"}); err == nil {
		t.Fatalf("expected self-parent department to be rejected")
	}
	missingParent := "d-missing"
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "d-orphan", Name: "Orphan", ParentID: &missingParent, Path: "/orphan"}); err == nil {
		t.Fatalf("expected missing parent department to be rejected")
	}
	grandchildParent := "d-grandchild"
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "d-root", Name: "Root", ParentID: &grandchildParent, Path: "/root"}); err == nil {
		t.Fatalf("expected cyclic department hierarchy to be rejected")
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "admin", Name: "Admin", Permissions: []string{"crm.customer.edit", "crm.customer.view"}, RecordScope: "all_records"}})
	keys, err := service.EffectivePermissionKeys(t.Context(), "u-admin")
	if err != nil {
		t.Fatalf("effective permissions: %v", err)
	}
	if len(keys) != 2 || keys[0] != "crm.customer.edit" || keys[1] != "crm.customer.view" {
		t.Fatalf("unexpected effective permissions: %#v", keys)
	}
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{ID: "u-temp", Name: "Temp", Email: "temp@example.com"}); err != nil {
		t.Fatalf("upsert temporary user: %v", err)
	}
	seedIdentityDirectoryRole(t, repo, identitymodel.InstallationWorkspaceID, identitymodel.IdentityRole{ID: "r-temp-active", Key: "temp_active", Label: "Temporary Active"})
	seedIdentityDirectoryRole(t, repo, identitymodel.InstallationWorkspaceID, identitymodel.IdentityRole{ID: "r-temp-expired", Key: "temp_expired", Label: "Temporary Expired"})
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "admin", Name: "Admin", Permissions: []string{"crm.customer.edit", "crm.customer.view"}, RecordScope: "all_records"},
		{Key: "temp_active", Name: "Temporary Active", Permissions: []string{"crm.customer.view"}, RecordScope: "all_records"},
		{Key: "temp_expired", Name: "Temporary Expired", Permissions: []string{"crm.customer.edit"}, RecordScope: "all_records"},
	})
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "u-temp", RoleID: "r-temp-active", ExpiresAt: &future}); err != nil {
		t.Fatalf("assign active temporary role: %v", err)
	}
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "u-temp", RoleID: "r-temp-expired", ExpiresAt: &past}); err != nil {
		t.Fatalf("assign expired temporary role: %v", err)
	}
	keys, err = service.EffectivePermissionKeys(t.Context(), "u-temp")
	if err != nil {
		t.Fatalf("effective permissions for temporary user: %v", err)
	}
	if len(keys) != 1 || keys[0] != "crm.customer.view" {
		t.Fatalf("expired temporary role should be ignored, got %#v", keys)
	}
	badExpiry := "tomorrow"
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "u-temp", RoleID: "r-temp-active", ExpiresAt: &badExpiry}); err == nil {
		t.Fatalf("expected invalid temporary role expiration to be rejected")
	}
	principal, err := service.BuildPrincipal(t.Context(), "u-admin")
	if err != nil {
		t.Fatalf("build principal: %v", err)
	}
	if principal.Role.Key != "admin" {
		t.Fatalf("single identity role should keep its role key, got %q", principal.Role.Key)
	}
	if !identitypolicy.IdentityRoleAllows(principal.Role, "customer", "edit") {
		t.Fatalf("expected identity principal to allow customer edit, got %#v", principal.Role.Permissions)
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "admin", Name: "Admin", Permissions: []string{"crm.customer.view"}, RecordScope: "all_records"},
		{Key: "temp_active", Name: "Temporary Active", Permissions: []string{"crm.customer.view"}, RecordScope: "all_records"},
		{Key: "temp_expired", Name: "Temporary Expired", Permissions: []string{"crm.customer.edit"}, RecordScope: "all_records"},
	})
	principal, err = service.BuildPrincipal(t.Context(), "u-admin")
	if err != nil {
		t.Fatalf("build principal after permission change: %v", err)
	}
	if identitypolicy.IdentityRoleAllows(principal.Role, "customer", "edit") {
		t.Fatalf("role permission changes should affect identity principal, got %#v", principal.Role.Permissions)
	}
	if err := service.SetUserStatus(t.Context(), "u-admin", identitymodel.IdentityStatusDisabled); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	keys, err = service.EffectivePermissionKeys(t.Context(), "u-admin")
	if err != nil {
		t.Fatalf("effective permissions for disabled user: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("disabled user should not receive permissions, got %#v", keys)
	}
}

func TestIdentityServiceRejectsDuplicateMenuKeys(t *testing.T) {
	repo := identitypersistence.NewMemoryIdentityStore()
	service, _ := identitybusiness.NewIdentityDomainService(repo, nil).ForWorkspace(identitymodel.InstallationWorkspaceID)
	if err := service.UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "menu-a", Key: "org_users", Label: "Users"}); err != nil {
		t.Fatalf("upsert first menu: %v", err)
	}
	if err := service.UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "menu-b", Key: "ORG_USERS", Label: "Duplicate"}); err == nil {
		t.Fatal("expected duplicate menu key to be rejected")
	}
	if err := service.UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "menu-a", Key: "org_users", Label: "Updated users"}); err != nil {
		t.Fatalf("updating the existing menu should remain valid: %v", err)
	}
}

func TestIdentityServiceValidatesMenuHierarchy(t *testing.T) {
	repo := identitypersistence.NewMemoryIdentityStore()
	service, _ := identitybusiness.NewIdentityDomainService(repo, nil).ForWorkspace(identitymodel.InstallationWorkspaceID)
	if err := service.UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "root", Key: "root", Label: "Root"}); err != nil {
		t.Fatalf("upsert root menu: %v", err)
	}
	if err := service.UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "child", Key: "child", Label: "Child", ParentID: "root"}); err != nil {
		t.Fatalf("upsert child menu: %v", err)
	}
	if err := service.UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "missing", Key: "missing", ParentID: "unknown"}); err == nil || !strings.Contains(err.Error(), "backend.identity.menu_parent_not_found") {
		t.Fatalf("expected missing parent error, got %v", err)
	}
	if err := service.UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "self", Key: "self", ParentID: "self"}); err == nil || !strings.Contains(err.Error(), "backend.identity.menu_parent_self") {
		t.Fatalf("expected self parent error, got %v", err)
	}
	if err := service.UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "root", Key: "root", Label: "Root", ParentID: "child"}); err == nil || !strings.Contains(err.Error(), "backend.identity.menu_parent_cycle") {
		t.Fatalf("expected menu cycle error, got %v", err)
	}
}

func TestIdentityServiceRejectsDuplicateUserEmails(t *testing.T) {
	repo := identitypersistence.NewMemoryIdentityStore()
	service, _ := identitybusiness.NewIdentityDomainService(repo, nil).ForWorkspace(identitymodel.InstallationWorkspaceID)
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{ID: "user-a", Name: "A", Email: "Person@Example.com"}); err != nil {
		t.Fatalf("upsert first user: %v", err)
	}
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{ID: "user-b", Name: "B", Email: "person@example.com"}); err == nil {
		t.Fatal("expected duplicate user email to be rejected")
	}
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{ID: "user-a", Name: "Updated A", Email: "PERSON@example.com"}); err != nil {
		t.Fatalf("updating the existing user should remain valid: %v", err)
	}
}

func TestIdentityServiceRejectsMissingAndDuplicateSiblingDepartmentNames(t *testing.T) {
	repo := identitypersistence.NewMemoryIdentityStore()
	service, _ := identitybusiness.NewIdentityDomainService(repo, nil).ForWorkspace(identitymodel.InstallationWorkspaceID)
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "root-a", Name: "Company"}); err != nil {
		t.Fatalf("upsert first root department: %v", err)
	}
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "root-b", Name: " company "}); err == nil {
		t.Fatal("expected duplicate root department name to be rejected")
	}
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "root-b", Name: "Division"}); err != nil {
		t.Fatalf("upsert second root department: %v", err)
	}
	rootA := "root-a"
	rootB := "root-b"
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "child-a", Name: "Sales", ParentID: &rootA}); err != nil {
		t.Fatalf("upsert first child department: %v", err)
	}
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "child-b", Name: "SALES", ParentID: &rootA}); err == nil {
		t.Fatal("expected duplicate sibling department name to be rejected")
	}
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "child-b", Name: "Sales", ParentID: &rootB}); err != nil {
		t.Fatalf("same department name under a different parent should remain valid: %v", err)
	}
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "child-a", Name: " SALES ", ParentID: &rootA}); err != nil {
		t.Fatalf("updating the existing department should remain valid: %v", err)
	}
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "missing-name", Name: "  "}); err == nil {
		t.Fatal("expected blank department name to be rejected")
	}
}

func TestIdentityServiceKeepsDepartmentSortOrder(t *testing.T) {
	repo := identitypersistence.NewMemoryIdentityStore()
	service, _ := identitybusiness.NewIdentityDomainService(repo, nil).ForWorkspace(identitymodel.InstallationWorkspaceID)
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "later", Name: "Later", SortOrder: 20}); err != nil {
		t.Fatalf("upsert later department: %v", err)
	}
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "earlier", Name: "Earlier", SortOrder: 10}); err != nil {
		t.Fatalf("upsert earlier department: %v", err)
	}
	departments, err := service.ListDepartments(t.Context())
	if err != nil {
		t.Fatalf("list departments: %v", err)
	}
	if len(departments) != 2 || departments[0].ID != "earlier" || departments[1].ID != "later" {
		t.Fatalf("expected department sort order to be preserved, got %#v", departments)
	}
}
