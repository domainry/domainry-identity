package identity

import (
	"net/http"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityAuthoringValidationHandlersUseExactCapabilityPayloads(t *testing.T) {
	repo := &identityHTTPRepository{
		roles: []identitymodel.IdentityRole{{ID: "sales_manager", Key: "sales_manager", Label: "Sales Manager", Status: identitymodel.IdentityStatusActive}},
		users: []identitymodel.IdentityUser{{ID: "sales_manager", Name: "Sales Manager", Email: "sales.manager@example.com", Status: identitymodel.IdentityStatusActive}},
		menus: []identitymodel.IdentityMenu{{ID: "orders", Key: "orders", Label: "Orders", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response := newIdentityHTTPHandler(repo)
	tests := []struct {
		name string
		body string
		call func(http.ResponseWriter, *http.Request)
	}{
		{name: "role", body: `{"id":"sales_manager","key":"sales_manager","label":"Sales Manager","status":"active"}`, call: handler.validateIdentityRoleAuthoring},
		{name: "role permission", body: `{"permission_keys":["customer.read"]}`, call: handler.validateIdentityRolePermissionAuthoring},
		{name: "role menu assignment", body: `{"menu_ids":["orders"]}`, call: handler.validateIdentityRoleMenuAssignmentAuthoring},
		{name: "user", body: `{"id":"sales_manager","name":"Sales Manager","email":"sales.manager@example.com","status":"active"}`, call: handler.validateIdentityUserAuthoring},
		{name: "department", body: `{"id":"sales","name":"Sales","status":"active"}`, call: handler.validateIdentityDepartmentAuthoring},
		{name: "user role assignment", body: `{"role_id":"sales_manager"}`, call: handler.validateIdentityUserRoleAssignmentAuthoring},
		{name: "role data scopes", body: `{"data_scopes":[]}`, call: handler.validateIdentityRoleDataScopeAuthoring},
		{name: "role field permissions", body: `{"field_permissions":[]}`, call: handler.validateIdentityRoleFieldPermissionAuthoring},
		{name: "menu", body: `{"id":"orders","key":"orders","label":"Orders","status":"active"}`, call: handler.validateIdentityMenuAuthoring},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response.status, response.value, response.err = 0, nil, nil
			writer, request := identityRoleRequest(http.MethodPost, "/identity/roles/sales_manager/validate", test.body, map[string]string{"roleID": "sales_manager", "userID": "sales_manager", "departmentID": "sales"})
			test.call(writer, request)
			if response.status != http.StatusOK || response.value == nil || response.err != nil {
				t.Fatalf("status=%d value=%#v err=%v", response.status, response.value, response.err)
			}
		})
	}
}

func TestIdentityAuthoringValidationHandlersCoverDecodeAndGovernanceErrors(t *testing.T) {
	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
	tests := []struct {
		name string
		body string
		call func(http.ResponseWriter, *http.Request)
	}{
		{name: "user", body: `{}`, call: handler.validateIdentityUserAuthoring},
		{name: "department", body: `{}`, call: handler.validateIdentityDepartmentAuthoring},
		{name: "user role", body: `{"role_id":"missing"}`, call: handler.validateIdentityUserRoleAssignmentAuthoring},
		{name: "role", body: `{}`, call: handler.validateIdentityRoleAuthoring},
		{name: "role permissions", body: `{"permission_keys":["missing"]}`, call: handler.validateIdentityRolePermissionAuthoring},
		{name: "role menus", body: `{"menu_ids":["missing"]}`, call: handler.validateIdentityRoleMenuAssignmentAuthoring},
		{name: "role scopes", body: `{"data_scopes":[{}]}`, call: handler.validateIdentityRoleDataScopeAuthoring},
		{name: "role fields", body: `{"field_permissions":[{}]}`, call: handler.validateIdentityRoleFieldPermissionAuthoring},
		{name: "menu", body: `{"key":"menu","label":"Menu","parent_id":"absent","status":"active"}`, call: handler.validateIdentityMenuAuthoring},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			for _, body := range []string{`{`, testCase.body} {
				response.status, response.value, response.err = 0, nil, nil
				writer, request := identityRoleRequest(http.MethodPost, "/validate", body, map[string]string{"roleID": "missing", "userID": "missing", "departmentID": "missing", "menuID": "missing"})
				testCase.call(writer, request)
				if response.status == http.StatusOK {
					t.Fatalf("body %q unexpectedly succeeded: %#v", body, response.value)
				}
			}
		})
	}
}
