package identity

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	metadataapplication "github.com/domainry/domainry-identity/internal/application/metadata"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
)

type identityLocalizationRepository struct {
	metadatarepository.MetadataRepository
	values []metadatamodel.LocalizedText
	err    error
}

func (r *identityLocalizationRepository) ListLocalizedTexts(context.Context, string, metadatamodel.LocalizedTextQuery) ([]metadatamodel.LocalizedText, error) {
	return append([]metadatamodel.LocalizedText(nil), r.values...), r.err
}

func TestIdentityMenuReadAndLocalizationHelpers(t *testing.T) {
	repo := &identityHTTPRepository{
		menus:     []identitymodel.IdentityMenu{{MenuID: "menu-1", Key: "customers", Label: "Customers"}},
		menuLinks: []identitymodel.IdentityRoleMenuAssignment{{RoleID: "role-1", MenuID: "menu-1"}},
	}
	handler, response := newIdentityHTTPHandler(repo)
	tests := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		path map[string]string
	}{
		{name: "permissions", call: handler.listIdentityPermissions},
		{name: "menus", call: handler.listIdentityMenus},
		{name: "role menus", call: handler.listIdentityRoleMenus, path: map[string]string{"roleID": " role-1 "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response.status, response.err, response.value = 0, nil, nil
			w, request := identityRoleRequest(http.MethodGet, "/identity/test", "", tt.path)
			tt.call(w, request)
			if response.status != http.StatusOK || response.err != nil || response.value == nil {
				t.Fatalf("response = status %d value %#v err %v", response.status, response.value, response.err)
			}
		})
	}
	if repo.lastRoleID != "role-1" {
		t.Fatalf("role id = %q", repo.lastRoleID)
	}
	w, request := identityRoleRequest(http.MethodGet, "/identity/roles/role-1/menus", "", map[string]string{"roleID": "role-1"})
	handler.listIdentityRoleMenus(w, request)
	if got := w.Header().Get(identityResourceHashHeader); got == "" || got == "empty" {
		t.Fatalf("role menu resource hash = %q", got)
	}

	request = mustIdentityMenuRequest(t, "/identity/menus")
	menus := []identitymodel.IdentityMenu{{MenuID: "menu-1", Label: "Original"}}
	if got := handler.LocalizedMenus(request, menus); len(got) != 1 || got[0].Label != "Original" {
		t.Fatalf("menus without locale = %#v", got)
	}
	permissions := []identitymodel.IdentityPermissionDefinition{{Key: "customer.read", Label: "Original"}}
	if got := handler.localizedIdentityPermissions(request, permissions); len(got) != 1 || got[0].Label != "Original" {
		t.Fatalf("permissions without locale = %#v", got)
	}

	values := []metadatamodel.LocalizedText{
		{EntityType: "menu", EntityKey: "customers", Property: "label", Text: "客户"},
		{EntityType: "menu", EntityKey: "customers", Property: "description", Text: "客户列表"},
	}
	lookup := identityLocalizedTextLookup(values)
	if lookup[identityLocalizedTextLookupKey(" menu ", " customers ", " label ")] != "客户" {
		t.Fatalf("localized lookup = %#v", lookup)
	}
}

func TestIdentityPermissionEnablementChangesDatabaseBackedSnapshot(t *testing.T) {
	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
	permissionKey := "identity.organization_units.list"
	if !handler.permissionCatalog.PermissionIsExecutable(permissionKey) {
		t.Fatalf("test permission %q was not initialized", permissionKey)
	}
	w, request := identityRoleRequest(http.MethodPut, "/identity/permissions/"+permissionKey+"/enabled", `{"enabled":false,"business_reason":"temporarily suspend organizationUnit projection access"}`, map[string]string{"permissionKey": permissionKey})
	handler.setIdentityPermissionEnabled(w, request)
	if response.status != http.StatusOK || response.err != nil {
		t.Fatalf("enablement response status=%d value=%#v err=%v", response.status, response.value, response.err)
	}
	if handler.permissionCatalog.PermissionIsExecutable(permissionKey) {
		t.Fatal("disabled permission remained executable")
	}
}

func TestIdentityMenuAndPermissionLocalization(t *testing.T) {
	repository := &identityLocalizationRepository{values: []metadatamodel.LocalizedText{
		{EntityType: "menu", EntityKey: "customers", Property: "name", Text: "客户"},
		{EntityType: "menu", EntityKey: "customers", Property: "description", Text: "客户列表"},
		{EntityType: "menu", EntityKey: "orders", Property: "label", Text: "订单"},
		{EntityType: "permission", EntityKey: "customer.read", Property: "label", Text: "读取客户"},
		{EntityType: "permission", EntityKey: "customer.read", Property: "description", Text: "查看客户"},
		{EntityType: "permission", EntityKey: "customer.read", Property: "resource_label", Text: "客户"},
		{EntityType: "permission", EntityKey: "order.read", Property: "name", Text: "读取订单"},
	}}
	handler, _ := newIdentityHTTPHandler(&identityHTTPRepository{})
	handler.localization = metadataapplication.NewMetadataApplicationService(metadataapplication.MetadataApplicationDependencies{Repository: repository})
	request := mustIdentityMenuRequest(t, "/identity/menus?locale=zh-CN")

	menus := []identitymodel.IdentityMenu{{MenuID: "customers", Label: "Customers"}, {MenuID: "orders", Key: "orders", Label: "Orders"}, {MenuID: "other", Key: "other", Label: "Other"}}
	localizedMenus := handler.LocalizedMenus(request, menus)
	if localizedMenus[0].Label != "客户" || localizedMenus[0].Description != "客户列表" || localizedMenus[1].Label != "订单" || menus[0].Label != "Customers" || localizedMenus[2].Label != "Other" {
		t.Fatalf("localized menus = %#v; original = %#v", localizedMenus, menus)
	}

	permissions := []identitymodel.IdentityPermissionDefinition{{Key: "customer.read", Label: "Read"}, {Key: "order.read", Label: "Orders"}, {Key: "other.read", Label: "Other"}}
	localizedPermissions := handler.localizedIdentityPermissions(request, permissions)
	if localizedPermissions[0].Label != "读取客户" || localizedPermissions[0].Description != "查看客户" || localizedPermissions[0].ResourceLabel != "客户" || localizedPermissions[1].Label != "读取订单" || permissions[0].Label != "Read" || localizedPermissions[2].Label != "Other" {
		t.Fatalf("localized permissions = %#v; original = %#v", localizedPermissions, permissions)
	}

	repository.values = nil
	if got := handler.LocalizedMenus(request, menus); got[0].Label != "Customers" {
		t.Fatalf("empty localization changed menus: %#v", got)
	}
	if got := handler.localizedIdentityPermissions(request, permissions); got[0].Label != "Read" {
		t.Fatalf("empty localization changed permissions: %#v", got)
	}
	repository.err = errors.New("localization unavailable")
	if got := handler.LocalizedMenus(request, menus); got[0].Label != "Customers" {
		t.Fatalf("failed localization changed menus: %#v", got)
	}
	if got := handler.localizedIdentityPermissions(request, permissions); got[0].Label != "Read" {
		t.Fatalf("failed localization changed permissions: %#v", got)
	}
}

func TestIdentityPermissionLocalizationUsesSourceOwnedCatalogText(t *testing.T) {
	handler, _ := newIdentityHTTPHandler(&identityHTTPRepository{})
	handler.localization = metadataapplication.NewMetadataApplicationService(metadataapplication.MetadataApplicationDependencies{Repository: &identityLocalizationRepository{}})
	permissions := []identitymodel.IdentityPermissionDefinition{{
		Key: "customer.read", Label: "Default", ResourceLabel: "default resource", ActionLabel: "default action", Description: "default description",
		I18n: identitymodel.IdentityPermissionLocalizedText{
			"zh-CN": {Label: "客户 · 查看", ResourceLabel: "客户", OperationLabel: "查看", Description: "查看客户"},
			"en":    {Label: "Accounts · View", ResourceLabel: "Accounts", OperationLabel: "View", Description: "View accounts"},
		},
	}}

	english := handler.localizedIdentityPermissions(mustIdentityMenuRequest(t, "/identity/permissions?locale=en-US"), permissions)
	if got := english[0]; got.Label != "Accounts · View" || got.ResourceLabel != "Accounts" || got.ActionLabel != "View" || got.Description != "View accounts" {
		t.Fatalf("English permission localization = %#v", got)
	}
	chinese := handler.localizedIdentityPermissions(mustIdentityMenuRequest(t, "/identity/permissions?locale=zh_CN"), permissions)
	if got := chinese[0]; got.Label != "客户 · 查看" || got.ResourceLabel != "客户" || got.ActionLabel != "查看" || got.Description != "查看客户" {
		t.Fatalf("Chinese permission localization = %#v", got)
	}
	if permissions[0].Label != "Default" || permissions[0].ResourceLabel != "default resource" {
		t.Fatalf("source permission mutated = %#v", permissions[0])
	}
}

func mustIdentityMenuRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	_, request := identityRoleRequest(http.MethodGet, target, "", nil)
	return request
}

func TestIdentityMenuMutationHandlers(t *testing.T) {
	repo := &identityHTTPRepository{
		roles:     []identitymodel.IdentityRole{{RoleID: "role-1", Key: "sales"}},
		menus:     []identitymodel.IdentityMenu{{MenuID: "menu-1", Key: "customers", Label: "Customers", Status: identitymodel.IdentityStatusActive}},
		menuLinks: []identitymodel.IdentityRoleMenuAssignment{{RoleID: "role-1", MenuID: "menu-1"}},
	}
	handler, response := newIdentityHTTPHandler(repo)

	w, request := identityRoleRequest(http.MethodPut, "/identity/menus/menu-2", `{"menu_id":"body-id","key":"orders","label":"Orders","route":"/orders"}`, map[string]string{"menuID": " menu-2 "})
	handler.upsertIdentityMenu(w, request)
	if response.status != http.StatusInternalServerError || response.err == nil || !strings.Contains(response.err.Error(), "global_menu_read_only") || repo.lastMenu.MenuID != "" {
		t.Fatalf("upsert response = status %d menu %#v err %v", response.status, repo.lastMenu, response.err)
	}

	response.status, response.err = 0, nil
	w, request = identityRoleRequest(http.MethodPut, "/identity/menus", `{"menu_id":"menu-2","key":"orders","label":"Orders","route":"/orders"}`, nil)
	handler.upsertIdentityMenu(w, request)
	if response.status != http.StatusInternalServerError || response.err == nil || !strings.Contains(response.err.Error(), "global_menu_read_only") || repo.lastMenu.MenuID != "" {
		t.Fatalf("body-id upsert = status %d menu %#v err %v", response.status, repo.lastMenu, response.err)
	}

	response.status, response.err = 0, nil
	w, request = identityRoleRequest(http.MethodDelete, "/identity/menus/menu-1", "", map[string]string{"menuID": " menu-1 "})
	handler.deleteIdentityMenu(w, request)
	if response.status != http.StatusInternalServerError || response.err == nil || !strings.Contains(response.err.Error(), "global_menu_read_only") || len(repo.lastMenuIDs) != 0 {
		t.Fatalf("delete response = status %d deleted %#v err %v", response.status, repo.lastMenuIDs, response.err)
	}

	repo.lastMenuIDs = nil
	response.status, response.err = 0, nil
	w, request = identityRoleRequest(http.MethodPut, "/identity/roles/role-1/menus", `{"menu_ids":["menu-1"]}`, map[string]string{"roleID": " role-1 "})
	handler.setIdentityRoleMenus(w, request)
	if response.status != http.StatusOK || response.err != nil || repo.lastRoleID != "role-1" || len(repo.lastMenuIDs) != 1 {
		t.Fatalf("set menus response = status %d role %q menus %#v err %v", response.status, repo.lastRoleID, repo.lastMenuIDs, response.err)
	}
}

func TestIdentityMenuHandlersRejectInvalidJSONAndServiceErrors(t *testing.T) {
	repo := &identityHTTPRepository{}
	handler, response := newIdentityHTTPHandler(repo)
	for _, call := range []func(http.ResponseWriter, *http.Request){handler.upsertIdentityMenu, handler.setIdentityRoleMenus} {
		response.status, response.err = 0, nil
		w, request := identityRoleRequest(http.MethodPut, "/identity/test", `{`, nil)
		call(w, request)
		if response.status != http.StatusBadRequest {
			t.Fatalf("invalid JSON status = %d", response.status)
		}
	}

	repo.err = errIdentityHTTPTest
	for _, call := range []func(http.ResponseWriter, *http.Request){handler.listIdentityMenus, handler.listIdentityRoleMenus} {
		response.status, response.err = 0, nil
		w, request := identityRoleRequest(http.MethodGet, "/identity/test", "", map[string]string{"menuID": "menu-1", "roleID": "role-1"})
		call(w, request)
		if response.err != errIdentityHTTPTest {
			t.Fatalf("service error = %v", response.err)
		}
	}
}

func TestIdentityMenuMutationServiceErrors(t *testing.T) {
	validMenus := []identitymodel.IdentityMenu{{MenuID: "menu-1", Key: "customers"}}
	validRoles := []identitymodel.IdentityRole{{RoleID: "role-1", Key: "sales"}}
	tests := []struct {
		name string
		repo *identityHTTPRepository
		call func(*IdentityHandler, http.ResponseWriter, *http.Request)
		body string
		path map[string]string
	}{
		{name: "set governance", repo: &identityHTTPRepository{menus: validMenus}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.setIdentityRoleMenus(w, r) }, body: `{"menu_ids":["menu-1"]}`, path: map[string]string{"roleID": "missing"}},
		{name: "set repository", repo: &identityHTTPRepository{menus: validMenus, roles: validRoles, setRoleMenusErr: errIdentityHTTPTest}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.setIdentityRoleMenus(w, r) }, body: `{"menu_ids":["menu-1"]}`, path: map[string]string{"roleID": "role-1"}},
		{name: "set relist", repo: &identityHTTPRepository{menus: validMenus, roles: validRoles, failListLinksAfterSet: true}, call: func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) { h.setIdentityRoleMenus(w, r) }, body: `{"menu_ids":["menu-1"]}`, path: map[string]string{"roleID": "role-1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(tt.repo)
			w, request := identityRoleRequest(http.MethodPut, "/identity/test", tt.body, tt.path)
			tt.call(handler, w, request)
			if response.err == nil || response.status != http.StatusInternalServerError {
				t.Fatalf("response = status %d err %v", response.status, response.err)
			}
		})
	}
}
