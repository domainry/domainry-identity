package identity_test

import (
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	identitybusiness "github.com/domainry/domainry-identity/internal/domain/identity/service"

	"testing"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestIdentityGovernanceValidationAggregatesCrossReferenceIssuesWithoutPersistence(t *testing.T) {
	objects := identityValidationObjects()
	store := identitypersistence.NewMemoryIdentityStore()
	identity, _ := identitybusiness.NewIdentityDomainService(store, []identitymodel.IdentityPermissionDefinition{currentPermission("order.read", "order", "read")}).ForWorkspace("workspace-a")
	seedIdentityProjectionRole(t, store, "workspace-a", identitymodel.IdentityRole{ID: "sales", Key: "sales", Label: "Sales", Status: identitymodel.IdentityStatusActive})
	if err := identity.UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "orders", Key: "orders", Label: "Orders", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	validator := identityapplication.NewIdentityGovernanceApplicationService(identity.Repository(), identity.PermissionDefinitions(), func() map[string]definitionmodel.ObjectSchema { return objects })
	menu := identitymodel.IdentityMenu{ID: "child", Key: "child", ParentID: "missing"}
	result, err := validator.Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{
		RoleID: "sales", Permissions: []identitymodel.RolePermission{
			{PermissionKey: "order.read", DataScope: identitymodel.IdentityDataScopeAll},
			{PermissionKey: "order.read", DataScope: identitymodel.IdentityDataScopeAll},
			{PermissionKey: "order.write", DataScope: "invented"},
		},
		FieldPermissions: []identitymodel.IdentityFieldPermission{{Resource: "order", Field: "missing", Editable: true}},
		Menu:             &menu, MenuIDs: []string{"orders", "orders", "missing"},
	}, identityGovernancePrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(result.Errors) != 8 {
		t.Fatalf("expected eight aggregated governance issues, got %#v", result)
	}
	expectedPaths := map[string]bool{
		"permissions[1].permission_key": true, "permissions[2].permission_key": true,
		"permissions[2].data_scope":  true,
		"field_permissions[0].field": true, "field_permissions[0].editable": true,
		"menu.parent_id": true, "menu_ids[1]": true, "menu_ids[2]": true,
	}
	for _, issue := range result.Errors {
		if !expectedPaths[issue.FieldPath] || issue.MessageKey == "" || issue.CapabilityKey == "" || issue.ContractVersion == "" {
			t.Fatalf("unexpected governance issue: %#v", issue)
		}
	}
	permissions, err := identity.ListRolePermissionAssignments(t.Context(), "sales")
	if err != nil || len(permissions) != 0 {
		t.Fatalf("validation persisted permissions: %#v err=%v", permissions, err)
	}
}

func TestIdentityGovernanceValidatorAcceptsExistingBusinessReferences(t *testing.T) {
	objects := identityValidationObjects()
	store := identitypersistence.NewMemoryIdentityStore()
	identity, _ := identitybusiness.NewIdentityDomainService(store, []identitymodel.IdentityPermissionDefinition{currentPermission("order.read", "order", "read")}).ForWorkspace("workspace-a")
	seedIdentityProjectionRole(t, store, "workspace-a", identitymodel.IdentityRole{ID: "sales", Key: "sales", Label: "Sales", Status: identitymodel.IdentityStatusActive})
	if err := identity.UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "orders", Key: "orders", Label: "Orders", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	result, err := identityapplication.NewIdentityGovernanceApplicationService(identity.Repository(), identity.PermissionDefinitions(), func() map[string]definitionmodel.ObjectSchema { return objects }).Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{
		RoleID: "sales", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "order.read"), MenuIDs: []string{"orders"},
		FieldPermissions: []identitymodel.IdentityFieldPermission{{Resource: "order", Field: "name", Visible: true, Editable: true}},
	}, identityGovernancePrincipal())
	if err != nil || !result.Valid || len(result.Errors) != 0 {
		t.Fatalf("valid governance result=%#v err=%v", result, err)
	}
}

func currentPermission(key, resource, action string) identitymodel.IdentityPermissionDefinition {
	return identitymodel.IdentityPermissionDefinition{
		Key: key, Resource: resource, Action: action,
		DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true,
	}
}

func TestIdentityGovernanceValidationAggregatesUserOrganizationUnitAndRoleAssignmentIssues(t *testing.T) {
	objects := map[string]definitionmodel.ObjectSchema{"identity_probe": {Key: "identity_probe", Name: "Identity Probe", Fields: []definitionmodel.FieldSchema{{Key: "name", Name: "Name", Type: "text"}}}}
	store := identitypersistence.NewMemoryIdentityStore()
	identity, _ := identitybusiness.NewIdentityDomainService(store, nil).ForWorkspace("workspace-a")
	if err := identity.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "sales", Code: "sales", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Sales"}); err != nil {
		t.Fatal(err)
	}
	if err := identity.UpsertUser(t.Context(), identitymodel.IdentityUser{ID: "manager", Name: "Manager", Email: "manager@example.com"}); err != nil {
		t.Fatal(err)
	}
	seedIdentityProjectionRole(t, store, "workspace-a", identitymodel.IdentityRole{ID: "sales-role", Key: "sales-role", Label: "Sales"})
	missingParent, invalidExpiry := "missing", "tomorrow"
	result, err := identityapplication.NewIdentityGovernanceApplicationService(identity.Repository(), identity.PermissionDefinitions(), func() map[string]definitionmodel.ObjectSchema { return objects }).Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{
		User:             &identitymodel.IdentityUser{ID: "candidate", Email: "not-an-email", Status: "invented"},
		OrganizationUnit: &identitymodel.IdentityOrganizationUnit{ID: "child", ParentID: &missingParent, Status: "invented"},
		RoleAssignment:   &identitymodel.IdentityUserRoleAssignment{UserID: "missing", RoleID: "missing", ExpiresAt: &invalidExpiry},
	}, identityGovernancePrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(result.Errors) != 11 {
		t.Fatalf("expected eleven aggregated identity configuration issues, got %#v", result)
	}
	expectedUserPaths := map[string]bool{
		"user.name": true, "user.email": true, "user.status": true,
	}
	for _, issue := range result.Errors {
		if issue.FieldPath == "" || issue.ErrorCode == "" || issue.MessageKey != issue.ErrorCode || issue.CapabilityKey == "" || issue.ContractVersion == "" {
			t.Fatalf("incomplete identity configuration issue: %#v", issue)
		}
		delete(expectedUserPaths, issue.FieldPath)
	}
	if len(expectedUserPaths) != 0 {
		t.Fatalf("missing account field validation paths: %#v", expectedUserPaths)
	}
}

func identityGovernancePrincipal() identitymodel.Principal {
	return identitymodel.Principal{Known: true, WorkspaceID: "workspace-a"}
}

func identityValidationObjects() map[string]definitionmodel.ObjectSchema {
	return map[string]definitionmodel.ObjectSchema{"order": {Key: "order", Name: "Order", Fields: []definitionmodel.FieldSchema{{Key: "name", Name: "Name", Type: "text"}}}}
}
