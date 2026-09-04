// Identity store and domain integration tests.
package identity_test

import (
	"strings"
	"testing"
	"time"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	identitybusiness "github.com/domainry/domainry-identity/internal/domain/identity/service"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestIdentityServiceValidatesPermissionsAndComputesEffectiveKeys(t *testing.T) {
	repo := identitypersistence.NewMemoryIdentityStore()
	service, _ := identitybusiness.NewIdentityDomainService(repo, []identitymodel.IdentityPermissionDefinition{
		currentPermission("crm.customer.view", "crm.customer", "view"),
		currentPermission("crm.customer.edit", "crm.customer", "edit"),
	}).ForWorkspace("workspace-primary")
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "company", Code: "company", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Company", Path: "/company"}); err != nil {
		t.Fatalf("upsert company organizationUnit: %v", err)
	}
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{ID: "u-admin", Name: "Admin", Email: "admin@example.com"}); err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	seedIdentityProjectionRole(t, repo, "workspace-primary", identitymodel.IdentityRole{ID: "r-admin", Key: "admin", Label: "Admin"})
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "u-admin", RoleID: "r-admin"}); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "d-root", Code: "d-root", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Root", Path: "/caller-controlled-root"}); err != nil {
		t.Fatalf("upsert root organizationUnit: %v", err)
	}
	rootParent := "d-root"
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "d-child", Code: "d-child", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Child", ParentID: &rootParent, Path: "/caller-controlled-child"}); err != nil {
		t.Fatalf("upsert child organizationUnit: %v", err)
	}
	childParent := "d-child"
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "d-grandchild", Code: "d-grandchild", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Grandchild", ParentID: &childParent, Path: "/caller-controlled-grandchild"}); err != nil {
		t.Fatalf("upsert grandchild organizationUnit: %v", err)
	}
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "d-child", Code: "d-child", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Child", ParentID: &rootParent, Path: "/still-not-authoritative"}); err != nil {
		t.Fatalf("move child organizationUnit: %v", err)
	}
	movedOrganizationUnits, err := service.ListOrganizationUnits(t.Context())
	if err != nil {
		t.Fatalf("list moved organizationUnits: %v", err)
	}
	movedOrganizationPaths := map[string]string{}
	for _, organizationUnit := range movedOrganizationUnits {
		movedOrganizationPaths[organizationUnit.ID] = organizationUnit.Path
	}
	if movedOrganizationPaths["d-root"] != "/d-root" || movedOrganizationPaths["d-child"] != "/d-root/d-child" || movedOrganizationPaths["d-grandchild"] != "/d-root/d-child/d-grandchild" {
		t.Fatalf("expected child organizationUnit path to be rebuilt, got %#v", movedOrganizationPaths)
	}
	selfParent := "d-self"
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "d-self", Code: "d-self", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Self", ParentID: &selfParent, Path: "/self"}); err == nil {
		t.Fatalf("expected self-parent organizationUnit to be rejected")
	}
	missingParent := "d-missing"
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "d-orphan", Code: "d-orphan", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Orphan", ParentID: &missingParent, Path: "/orphan"}); err == nil {
		t.Fatalf("expected missing parent organizationUnit to be rejected")
	}
	grandchildParent := "d-grandchild"
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "d-root", Code: "d-root", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Root", ParentID: &grandchildParent, Path: "/root"}); err == nil {
		t.Fatalf("expected cyclic organizationUnit hierarchy to be rejected")
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "admin", Name: "Admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "crm.customer.edit", "crm.customer.view")}})
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
	seedIdentityProjectionRole(t, repo, "workspace-primary", identitymodel.IdentityRole{ID: "r-temp-active", Key: "temp_active", Label: "Temporary Active"})
	seedIdentityProjectionRole(t, repo, "workspace-primary", identitymodel.IdentityRole{ID: "r-temp-expired", Key: "temp_expired", Label: "Temporary Expired"})
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "admin", Name: "Admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "crm.customer.edit", "crm.customer.view")},
		{Key: "temp_active", Name: "Temporary Active", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "crm.customer.view")},
		{Key: "temp_expired", Name: "Temporary Expired", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "crm.customer.edit")},
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
	if !identitycontract.IdentityRoleAllows(principal.Role, "crm.customer", "edit") {
		t.Fatalf("expected identity principal to allow customer edit, got %#v", principal.Role.Permissions)
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "admin", Name: "Admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "crm.customer.view")},
		{Key: "temp_active", Name: "Temporary Active", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "crm.customer.view")},
		{Key: "temp_expired", Name: "Temporary Expired", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "crm.customer.edit")},
	})
	principal, err = service.BuildPrincipal(t.Context(), "u-admin")
	if err != nil {
		t.Fatalf("build principal after permission change: %v", err)
	}
	if identitycontract.IdentityRoleAllows(principal.Role, "customer", "edit") {
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
	service, _ := identitybusiness.NewIdentityDomainService(repo, nil).ForWorkspace("workspace-primary")
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
	service, _ := identitybusiness.NewIdentityDomainService(repo, nil).ForWorkspace("workspace-primary")
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
	service, _ := identitybusiness.NewIdentityDomainService(repo, nil).ForWorkspace("workspace-primary")
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

func TestIdentityServiceRejectsMissingAndDuplicateSiblingOrganizationUnitNames(t *testing.T) {
	repo := identitypersistence.NewMemoryIdentityStore()
	service, _ := identitybusiness.NewIdentityDomainService(repo, nil).ForWorkspace("workspace-primary")
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "root-a", Code: "root-a", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Company"}); err != nil {
		t.Fatalf("upsert first root organizationUnit: %v", err)
	}
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "root-b", Code: "root-b", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: " company "}); err == nil {
		t.Fatal("expected duplicate root organizationUnit name to be rejected")
	}
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "root-b", Code: "root-b", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Division"}); err != nil {
		t.Fatalf("upsert second root organizationUnit: %v", err)
	}
	rootA := "root-a"
	rootB := "root-b"
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "child-a", Code: "child-a", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Sales", ParentID: &rootA}); err != nil {
		t.Fatalf("upsert first child organizationUnit: %v", err)
	}
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "child-b", Code: "child-b", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "SALES", ParentID: &rootA}); err == nil {
		t.Fatal("expected duplicate sibling organizationUnit name to be rejected")
	}
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "child-b", Code: "child-b", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Sales", ParentID: &rootB}); err != nil {
		t.Fatalf("same organizationUnit name under a different parent should remain valid: %v", err)
	}
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "child-a", Code: "child-a", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: " SALES ", ParentID: &rootA}); err != nil {
		t.Fatalf("updating the existing organizationUnit should remain valid: %v", err)
	}
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "missing-name", Code: "missing-name", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "  "}); err == nil {
		t.Fatal("expected blank organizationUnit name to be rejected")
	}
}

func TestIdentityServiceKeepsOrganizationUnitSortOrder(t *testing.T) {
	repo := identitypersistence.NewMemoryIdentityStore()
	service, _ := identitybusiness.NewIdentityDomainService(repo, nil).ForWorkspace("workspace-primary")
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "later", Code: "later", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Later", SortOrder: 20}); err != nil {
		t.Fatalf("upsert later organizationUnit: %v", err)
	}
	if err := service.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "earlier", Code: "earlier", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Earlier", SortOrder: 10}); err != nil {
		t.Fatalf("upsert earlier organizationUnit: %v", err)
	}
	organizationUnits, err := service.ListOrganizationUnits(t.Context())
	if err != nil {
		t.Fatalf("list organizationUnits: %v", err)
	}
	if len(organizationUnits) != 2 || organizationUnits[0].ID != "earlier" || organizationUnits[1].ID != "later" {
		t.Fatalf("expected organizationUnit sort order to be preserved, got %#v", organizationUnits)
	}
}
