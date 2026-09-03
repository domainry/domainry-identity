package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func identityGovernanceTestPrincipal() identitymodel.Principal {
	return identitymodel.Principal{Known: true, WorkspaceID: "workspace-a"}
}

func identityGovernanceTestService(repository identityrepository.IdentityRepository) *IdentityGovernanceApplicationService {
	return NewIdentityGovernanceApplicationService(
		repository,
		map[string]identitymodel.IdentityPermissionDefinition{"order.read": {Key: "order.read", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true}},
		func() map[string]definitionmodel.ObjectSchema {
			return map[string]definitionmodel.ObjectSchema{"order": {Key: "order", Fields: []definitionmodel.FieldSchema{{Key: "amount"}, {Key: "total_amount"}, {Key: "owner"}}}}
		},
	)
}

func TestIdentityGovernanceValidationReportsEveryReferenceShape(t *testing.T) {
	repository := &identityScopedRepository{
		roles: []identitymodel.IdentityRole{{ID: "existing", Key: "duplicate"}},
		menus: []identitymodel.IdentityMenu{
			{ID: "root", Key: "root"},
			{ID: "ancestor", Key: "ancestor", ParentID: "candidate"},
			{ID: "other", Key: "duplicate-menu"},
		},
	}
	service := identityGovernanceTestService(repository)
	role := identitymodel.IdentityRole{
		ID: "candidate", Key: " DUPLICATE ",
	}
	permissions := []identitymodel.RolePermission{
		{PermissionKey: "order.read", DataScope: identitymodel.IdentityDataScopeAll},
		{PermissionKey: " order.read ", DataScope: "invalid"},
		{PermissionKey: "missing", DataScope: identitymodel.IdentityDataScopeAll},
		{PermissionKey: "", DataScope: identitymodel.IdentityDataScopeAll},
	}
	fieldPermissions := []identitymodel.IdentityFieldPermission{
		{Resource: "order", Field: "amount", Visible: true},
		{Resource: "order", Field: "amount", Editable: true},
		{Resource: "order", Field: "missing", Visible: true},
		{Resource: "missing", Field: "amount", Visible: true},
	}
	menu := identitymodel.IdentityMenu{ID: "candidate", Key: " duplicate-menu ", ParentID: "ancestor"}
	result, err := service.Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{
		Role:             &role,
		RoleID:           "missing-role",
		Permissions:      permissions,
		FieldPermissions: fieldPermissions,
		Menu:             &menu,
		MenuIDs:          []string{"root", " root ", "missing", ""},
	}, identityGovernanceTestPrincipal())
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.ContractVersion != identitycontract.IdentityAuthoringContractVersion {
		t.Fatalf("result = %#v", result)
	}
	codes := map[string]bool{}
	for _, issue := range result.Errors {
		codes[issue.ErrorCode] = true
		if issue.ContractVersion != identitycontract.IdentityAuthoringContractVersion || issue.MessageKey != issue.ErrorCode || issue.CapabilityKey == "" {
			t.Fatalf("unstable issue = %#v", issue)
		}
	}
	for _, code := range []string{
		"backend.identity.role_key_exists",
		"backend.identity.permission_duplicate",
		"backend.identity.permission_not_found",
		"backend.identity.data_scope_invalid",
		"backend.identity.field_permission_duplicate",
		"backend.identity.field_permission_edit_requires_visibility",
		"backend.identity.field_permission_field_not_found",
		"backend.identity.field_permission_resource_not_found",
		"backend.identity.role_not_found",
		"backend.identity.menu_key_exists",
		"backend.identity.menu_parent_cycle",
		"backend.identity.menu_assignment_duplicate",
		"backend.identity.menu_not_found",
	} {
		if !codes[code] {
			t.Errorf("missing issue %s in %#v", code, result.Errors)
		}
	}
}

func TestIdentityGovernanceValidationAcceptsCanonicalConfiguration(t *testing.T) {
	repository := &identityScopedRepository{
		roles: []identitymodel.IdentityRole{{ID: "role", Key: "role"}},
		menus: []identitymodel.IdentityMenu{{ID: "root", Key: "root"}},
	}
	service := identityGovernanceTestService(repository)
	role := identitymodel.IdentityRole{ID: "role", Key: "role"}
	menu := identitymodel.IdentityMenu{ID: "child", Key: "child", ParentID: "root"}
	result, err := service.Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{Role: &role, RoleID: "role", Permissions: identityTestRolePermissions("order.read"), FieldPermissions: []identitymodel.IdentityFieldPermission{{Resource: "order", Field: "amount", Visible: true}}, Menu: &menu, MenuIDs: []string{"root"}}, identityGovernanceTestPrincipal())
	if err != nil || !result.Valid || len(result.Errors) != 0 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestIdentityOwnerAuthoringExamplesUseRealGovernanceValidator(t *testing.T) {
	repository := &identityScopedRepository{
		roles:             []identitymodel.IdentityRole{{ID: "role", Key: "role"}, {ID: "sales_role", Key: "sales_role"}},
		users:             []identitymodel.IdentityUser{{ID: "sales_manager", Name: "Sales Manager", Email: "sales.manager@example.com", Status: identitymodel.IdentityStatusActive}},
		organizationUnits: []identitymodel.IdentityOrganizationUnit{{ID: "company", Name: "Company", Status: identitymodel.IdentityStatusActive}, {ID: "sales", Name: "Sales", Status: identitymodel.IdentityStatusActive}},
		menus:             []identitymodel.IdentityMenu{{ID: "root", Key: "root"}, {ID: "orders", Key: "orders"}, {ID: "reports", Key: "reports"}},
	}
	service := identityGovernanceTestService(repository)
	principal := identityGovernanceTestPrincipal()

	field := identitycontract.IdentityRoleFieldPermissionAuthoringCapability()
	for _, example := range field.Examples[:2] {
		var request struct {
			FieldPermissions []identitymodel.IdentityFieldPermission `json:"field_permissions"`
		}
		decodeIdentityAuthoringExample(t, example.Value, &request)
		if err := service.ValidateRoleFieldPermissions(t.Context(), "role", request.FieldPermissions, principal); err != nil {
			t.Fatalf("field permission example %s: %v", example.Name, err)
		}
	}
	var invalidFields struct {
		FieldPermissions []identitymodel.IdentityFieldPermission `json:"field_permissions"`
	}
	decodeIdentityAuthoringExample(t, field.Examples[2].Value, &invalidFields)
	if err := service.ValidateRoleFieldPermissions(t.Context(), "role", invalidFields.FieldPermissions, principal); apperror.CodeOf(err) != field.Examples[2].ExpectedErrorCodes[0] {
		t.Fatalf("invalid field permission error=%v", err)
	}

	menu := identitycontract.IdentityMenuAuthoringCapability()
	for _, example := range menu.Examples[:2] {
		var value identitymodel.IdentityMenu
		decodeIdentityAuthoringExample(t, example.Value, &value)
		if err := service.ValidateMenu(t.Context(), value, principal); err != nil {
			t.Fatalf("menu example %s: %v", example.Name, err)
		}
	}
	var invalidMenu identitymodel.IdentityMenu
	decodeIdentityAuthoringExample(t, menu.Examples[2].Value, &invalidMenu)
	if err := service.ValidateMenu(t.Context(), invalidMenu, principal); apperror.CodeOf(err) != menu.Examples[2].ExpectedErrorCodes[0] {
		t.Fatalf("invalid menu error=%v", err)
	}

	roleMenus := identitycontract.IdentityRoleMenuAssignmentAuthoringCapability()
	for _, example := range roleMenus.Examples[:2] {
		var request struct {
			MenuIDs []string `json:"menu_ids"`
		}
		decodeIdentityAuthoringExample(t, example.Value, &request)
		if err := service.ValidateRoleMenus(t.Context(), "role", request.MenuIDs, principal); err != nil {
			t.Fatalf("role menu example %s: %v", example.Name, err)
		}
	}
	var invalidRoleMenus struct {
		MenuIDs []string `json:"menu_ids"`
	}
	decodeIdentityAuthoringExample(t, roleMenus.Examples[2].Value, &invalidRoleMenus)
	if err := service.ValidateRoleMenus(t.Context(), "role", invalidRoleMenus.MenuIDs, principal); apperror.CodeOf(err) != roleMenus.Examples[2].ExpectedErrorCodes[0] {
		t.Fatalf("invalid role menu error=%v", err)
	}

	user := identitycontract.IdentityUserAuthoringCapability()
	for _, example := range user.Examples[:2] {
		var value identitymodel.IdentityUser
		decodeIdentityAuthoringExample(t, example.Value, &value)
		if err := service.ValidateUser(t.Context(), value, principal); err != nil {
			t.Fatalf("user example %s: %v", example.Name, err)
		}
	}
	var invalidUser identitymodel.IdentityUser
	decodeIdentityAuthoringExample(t, user.Examples[2].Value, &invalidUser)
	if err := service.ValidateUser(t.Context(), invalidUser, principal); apperror.CodeOf(err) != user.Examples[2].ExpectedErrorCodes[0] {
		t.Fatalf("invalid user error=%v", err)
	}

	organizationUnit := identitycontract.IdentityOrganizationUnitAuthoringCapability()
	for _, example := range organizationUnit.Examples[:2] {
		var value identitymodel.IdentityOrganizationUnit
		decodeIdentityAuthoringExample(t, example.Value, &value)
		if err := service.ValidateOrganizationUnit(t.Context(), value, principal); err != nil {
			t.Fatalf("organizationUnit example %s: %v", example.Name, err)
		}
	}
	var invalidOrganizationUnit identitymodel.IdentityOrganizationUnit
	decodeIdentityAuthoringExample(t, organizationUnit.Examples[2].Value, &invalidOrganizationUnit)
	if err := service.ValidateOrganizationUnit(t.Context(), invalidOrganizationUnit, principal); apperror.CodeOf(err) != organizationUnit.Examples[2].ExpectedErrorCodes[0] {
		t.Fatalf("invalid organizationUnit error=%v", err)
	}

	assignment := identitycontract.IdentityUserRoleAssignmentAuthoringCapability()
	for _, example := range assignment.Examples[:2] {
		var request struct {
			RoleID    string  `json:"role_id"`
			ExpiresAt *string `json:"expires_at,omitempty"`
		}
		decodeIdentityAuthoringExample(t, example.Value, &request)
		value := identitymodel.IdentityUserRoleAssignment{UserID: "sales_manager", RoleID: request.RoleID, ExpiresAt: request.ExpiresAt}
		if err := service.ValidateUserRoleAssignment(t.Context(), value, principal); err != nil {
			t.Fatalf("assignment example %s: %v", example.Name, err)
		}
	}
	var invalidAssignmentRequest struct {
		RoleID    string  `json:"role_id"`
		ExpiresAt *string `json:"expires_at,omitempty"`
	}
	decodeIdentityAuthoringExample(t, assignment.Examples[2].Value, &invalidAssignmentRequest)
	invalidAssignment := identitymodel.IdentityUserRoleAssignment{UserID: "sales_manager", RoleID: invalidAssignmentRequest.RoleID, ExpiresAt: invalidAssignmentRequest.ExpiresAt}
	if err := service.ValidateUserRoleAssignment(t.Context(), invalidAssignment, principal); apperror.CodeOf(err) != assignment.Examples[2].ExpectedErrorCodes[0] {
		t.Fatalf("invalid assignment error=%v", err)
	}
}

func decodeIdentityAuthoringExample(t *testing.T, value map[string]any, target any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityGovernanceValidationIncludesConfigurationSections(t *testing.T) {
	repository := &identityScopedRepository{
		organizationUnits: []identitymodel.IdentityOrganizationUnit{{ID: "organizationUnit", Name: "OrganizationUnit"}},
		users:             []identitymodel.IdentityUser{{ID: "user", Name: "User", Email: "user@example.com"}},
		roles:             []identitymodel.IdentityRole{{ID: "role", Key: "role"}, {ID: "other", Key: "other"}},
		menus:             []identitymodel.IdentityMenu{{ID: "menu", Key: "menu"}},
	}
	service := identityGovernanceTestService(repository)
	user := identitymodel.IdentityUser{ID: "user", Name: "User", Email: "user@example.com"}
	organizationUnit := identitymodel.IdentityOrganizationUnit{ID: "organizationUnit", Name: "OrganizationUnit"}
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: "user", RoleID: "role"}
	role := identitymodel.IdentityRole{
		ID: "role", Key: "role",
	}
	menu := identitymodel.IdentityMenu{ID: "menu", Key: "menu"}
	result, err := service.Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{
		User: &user, OrganizationUnit: &organizationUnit, RoleAssignment: &assignment, Role: &role, Menu: &menu,
		FieldPermissions: []identitymodel.IdentityFieldPermission{{Resource: "", Field: ""}, {Resource: "order", Field: "", Editable: true}, {Resource: "order", Field: "amount", Visible: true, Editable: true}},
	}, identityGovernanceTestPrincipal())
	if err != nil || result.Valid {
		t.Fatalf("configuration result=%#v err=%v", result, err)
	}
}

type identityGovernanceStageFaultRepository struct {
	*identityScopedRepository
	stage string
}

func (r identityGovernanceStageFaultRepository) ListIdentityUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	if r.stage == "users" {
		return nil, errIdentitySeedTest
	}
	return r.identityScopedRepository.ListIdentityUsers(ctx, workspaceID)
}

func (r identityGovernanceStageFaultRepository) ListIdentityOrganizationUnits(ctx context.Context, workspaceID string) ([]identitymodel.IdentityOrganizationUnit, error) {
	if r.stage == "organizationUnits" {
		return nil, errIdentitySeedTest
	}
	return r.identityScopedRepository.ListIdentityOrganizationUnits(ctx, workspaceID)
}

func (r identityGovernanceStageFaultRepository) GetIdentityUser(ctx context.Context, workspaceID, userID string) (identitymodel.IdentityUser, bool, error) {
	if r.stage == "assignment_user" {
		return identitymodel.IdentityUser{}, false, errIdentitySeedTest
	}
	return r.identityScopedRepository.GetIdentityUser(ctx, workspaceID, userID)
}

func (r identityGovernanceStageFaultRepository) ListIdentityRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	if r.stage == "assignment_role" || r.stage == "role_reference" {
		return nil, errIdentitySeedTest
	}
	return r.identityScopedRepository.ListIdentityRoles(ctx, workspaceID)
}

func (r identityGovernanceStageFaultRepository) ListIdentityMenus(ctx context.Context, workspaceID string) ([]identitymodel.IdentityMenu, error) {
	if r.stage == "menu" || r.stage == "menu_references" {
		return nil, errIdentitySeedTest
	}
	return r.identityScopedRepository.ListIdentityMenus(ctx, workspaceID)
}

func TestIdentityGovernanceValidationPropagatesEveryConfigurationReadFailure(t *testing.T) {
	base := &identityScopedRepository{users: []identitymodel.IdentityUser{{ID: "user"}}, roles: []identitymodel.IdentityRole{{ID: "role"}}}
	user := identitymodel.IdentityUser{ID: "user", Name: "User", Email: "user@example.com"}
	organizationUnit := identitymodel.IdentityOrganizationUnit{ID: "organizationUnit", Name: "OrganizationUnit"}
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: "user", RoleID: "role"}
	menu := identitymodel.IdentityMenu{ID: "menu", Key: "menu"}
	tests := []struct {
		stage   string
		request identitycontract.IdentityGovernanceValidationRequest
	}{
		{stage: "users", request: identitycontract.IdentityGovernanceValidationRequest{User: &user}},
		{stage: "organizationUnits", request: identitycontract.IdentityGovernanceValidationRequest{OrganizationUnit: &organizationUnit}},
		{stage: "assignment_user", request: identitycontract.IdentityGovernanceValidationRequest{RoleAssignment: &assignment}},
		{stage: "assignment_role", request: identitycontract.IdentityGovernanceValidationRequest{RoleAssignment: &assignment}},
		{stage: "role_reference", request: identitycontract.IdentityGovernanceValidationRequest{RoleID: "role"}},
		{stage: "menu", request: identitycontract.IdentityGovernanceValidationRequest{Menu: &menu}},
		{stage: "menu_references", request: identitycontract.IdentityGovernanceValidationRequest{MenuIDs: []string{"menu"}}},
	}
	for _, test := range tests {
		t.Run(test.stage, func(t *testing.T) {
			service := identityGovernanceTestService(identityGovernanceStageFaultRepository{identityScopedRepository: base, stage: test.stage})
			if _, err := service.Validate(t.Context(), test.request, identityGovernanceTestPrincipal()); !errors.Is(err, errIdentitySeedTest) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	service := identityGovernanceTestService(identityGovernanceStageFaultRepository{identityScopedRepository: base, stage: "role_reference"})
	if err := service.ValidateRolePermissions(t.Context(), "role", nil, identityGovernanceTestPrincipal()); !errors.Is(err, errIdentitySeedTest) {
		t.Fatalf("firstError did not propagate validation failure: %v", err)
	}
}

func TestIdentityGovernanceConvenienceValidatorsReturnFirstStructuredError(t *testing.T) {
	service := identityGovernanceTestService(&identityScopedRepository{})
	principal := identityGovernanceTestPrincipal()
	tests := []struct {
		name string
		call func() error
	}{
		{name: "permissions", call: func() error {
			return service.ValidateRolePermissions(t.Context(), "missing", identityTestRolePermissions("missing"), principal)
		}},
		{name: "fields", call: func() error {
			return service.ValidateRoleFieldPermissions(t.Context(), "missing", []identitymodel.IdentityFieldPermission{{Resource: "missing", Field: "field"}}, principal)
		}},
		{name: "menus", call: func() error { return service.ValidateRoleMenus(t.Context(), "missing", []string{"missing"}, principal) }},
		{name: "menu", call: func() error { return service.ValidateMenu(t.Context(), identitymodel.IdentityMenu{}, principal) }},
		{name: "role", call: func() error { return service.ValidateRole(t.Context(), identitymodel.IdentityRole{}, principal) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			var appErr *apperror.AppError
			if !errors.As(err, &appErr) || appErr.Kind != apperror.KindBadRequest || appErr.Code == "" || appErr.Params["field_path"] == "" {
				t.Fatalf("error = %#v", err)
			}
		})
	}
	if err := service.ValidateRolePermissions(t.Context(), "", nil, principal); err != nil {
		t.Fatalf("empty valid request = %v", err)
	}
	err := identityGovernanceBadRequest("code", "", "ignored", "field", "value", "odd")
	var appErr *apperror.AppError
	if !errors.As(err, &appErr) || len(appErr.Params) != 1 || appErr.Params["field"] != "value" {
		t.Fatalf("bad request params = %#v", err)
	}
}

func TestIdentityGovernanceMenuParentEdges(t *testing.T) {
	service := identityGovernanceTestService(&identityScopedRepository{menus: []identitymodel.IdentityMenu{{ID: "root", Key: "root"}}})
	principal := identityGovernanceTestPrincipal()
	for name, menu := range map[string]identitymodel.IdentityMenu{
		"self":         {ID: "self", Key: "self", ParentID: "self"},
		"missing":      {ID: "child", Key: "child", ParentID: "missing"},
		"id fallback":  {Key: "key-only"},
		"key fallback": {ID: "id-only"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := service.Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{Menu: &menu}, principal)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

type identityGovernanceRoleFaultRepository struct {
	identityrepository.IdentityRepository
}

func (identityGovernanceRoleFaultRepository) ListIdentityRoles(context.Context, string) ([]identitymodel.IdentityRole, error) {
	return nil, errIdentitySeedTest
}

func (identityGovernanceRoleFaultRepository) ListIdentityMenus(context.Context, string) ([]identitymodel.IdentityMenu, error) {
	return nil, nil
}

func TestIdentityGovernanceRoleValidationPropagatesRepositoryFailure(t *testing.T) {
	service := identityGovernanceTestService(identityGovernanceRoleFaultRepository{})
	role := identitymodel.IdentityRole{ID: "role", Key: "role"}
	_, err := service.Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{Role: &role}, identityGovernanceTestPrincipal())
	if !errors.Is(err, errIdentitySeedTest) {
		t.Fatalf("repository failure was hidden: %v", err)
	}
}

func TestIdentityGovernanceRejectsMissingDependenciesAfterAuthorization(t *testing.T) {
	for name, service := range map[string]*IdentityGovernanceApplicationService{
		"nil service":    nil,
		"nil repository": NewIdentityGovernanceApplicationService(nil, nil, func() map[string]definitionmodel.ObjectSchema { return nil }),
		"nil objects":    NewIdentityGovernanceApplicationService(&identityScopedRepository{}, nil, nil),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := service.Validate(t.Context(), identitycontract.IdentityGovernanceValidationRequest{}, identityGovernanceTestPrincipal())
			if apperror.CodeOf(err) != "backend.internal" {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestIdentityGovernancePermissionValidationFailsClosedWithoutCatalog(t *testing.T) {
	service := NewIdentityGovernanceApplicationServiceWithPermissionSource(&identityScopedRepository{}, nil, func() map[string]definitionmodel.ObjectSchema { return nil })
	issues := service.validatePermissions(identityTestRolePermissions("missing"))
	if len(issues) != 1 || issues[0].ErrorCode != "backend.identity.permission_not_found" {
		t.Fatalf("issues=%#v", issues)
	}
}

func TestIdentityGovernancePermissionValidationUsesCurrentDefinitionState(t *testing.T) {
	service := NewIdentityGovernanceApplicationServiceWithPermissionSource(
		&identityScopedRepository{},
		func() map[string]identitymodel.IdentityPermissionDefinition {
			return map[string]identitymodel.IdentityPermissionDefinition{
				"active":   {Key: "active", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true},
				"disabled": {Key: "disabled", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: false},
				"retired":  {Key: "retired", DefinitionStatus: identitymodel.IdentityPermissionDefinitionRetired, Enabled: true},
			}
		},
		func() map[string]definitionmodel.ObjectSchema { return nil },
	)
	issues := service.validatePermissions(identityTestRolePermissions("active", "disabled", "retired", "missing"))
	if len(issues) != 3 || issues[0].ErrorCode != "backend.identity.permission_disabled" || issues[1].ErrorCode != "backend.identity.permission_retired" || issues[2].ErrorCode != "backend.identity.permission_not_found" {
		t.Fatalf("issues=%#v", issues)
	}
}
