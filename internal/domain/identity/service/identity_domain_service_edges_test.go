package service

import (
	"errors"
	"reflect"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityDomainConstructionAndPermissionCatalogEdges(t *testing.T) {
	var nilService *IdentityDomainService
	if nilService.Repository() != nil {
		t.Fatal("nil service exposed a repository")
	}
	nilService.UseRoleBindingEligibility(nil)
	nilService.UseOrganizationScopeResolver(nil)
	if nilService.WorkspaceID() != "" {
		t.Fatal("nil service exposed a workspace")
	}

	repository := &identityPermissionMenuRepository{}
	service := NewIdentityDomainService(repository, []identitymodel.IdentityPermissionDefinition{
		{Key: "z.permission", Label: "old"},
		{Key: ""},
		{Key: "a.permission"},
		{Key: "z.permission", Label: "new"},
	})
	if service.Repository() != repository {
		t.Fatal("repository identity changed")
	}
	if service.WorkspaceID() != "" {
		t.Fatalf("unscoped workspace=%q", service.WorkspaceID())
	}
	if _, err := service.ForWorkspace(" "); err == nil {
		t.Fatal("blank workspace was accepted")
	}
	scoped, err := service.ForWorkspace(" workspace ")
	if err != nil || scoped.workspace != "workspace" || scoped == service {
		t.Fatalf("scoped=%+v err=%v", scoped, err)
	}
	definitions := service.PermissionDefinitions()
	if len(definitions) != 2 || definitions["z.permission"].Label != "new" {
		t.Fatalf("definitions=%+v", definitions)
	}
	delete(definitions, "z.permission")
	if len(service.PermissionDefinitions()) != 2 {
		t.Fatal("permission definitions were not cloned")
	}
	permissions := service.ListPermissions(t.Context())
	if len(permissions) != 2 || permissions[0].Key != "a.permission" || permissions[1].Key != "z.permission" {
		t.Fatalf("permissions=%+v", permissions)
	}
	service.ReplacePermissionDefinitions([]identitymodel.IdentityPermissionDefinition{
		{Key: " "},
		{Key: " replacement.permission "},
	})
	if replaced := service.ListPermissions(t.Context()); len(replaced) != 1 || replaced[0].Key != "replacement.permission" {
		t.Fatalf("replaced permissions=%+v", replaced)
	}
	service.ReplaceAuthorizationPolicies(
		[]identitymodel.IdentityPermissionSet{{Key: " "}, {Key: " z-set "}, {Key: " a-set "}},
		[]identitymodel.IdentityPermissionSetGroup{{Key: " "}, {Key: " z-group "}, {Key: " a-group "}},
		[]identitymodel.IdentityGuardrailPolicy{{Key: " "}, {Key: " z-guardrail "}, {Key: " a-guardrail "}},
	)
	if sets, groups, guardrails := service.PublishedPermissionSets(t.Context()), service.PublishedPermissionSetGroups(t.Context()), service.PublishedGuardrails(t.Context()); len(sets) != 2 || sets[0].Key != "a-set" || len(groups) != 2 || groups[0].Key != "a-group" || len(guardrails) != 2 || guardrails[0].Key != "a-guardrail" {
		t.Fatalf("sets=%+v groups=%+v guardrails=%+v", sets, groups, guardrails)
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: " "}, {Key: " role "}})
	if _, found := service.PublishedRoleDefinition(t.Context(), " "); found {
		t.Fatal("blank role key was published")
	}
	if role, found := service.PublishedRoleDefinition(t.Context(), " role "); !found || role.Key != "role" {
		t.Fatalf("role=%+v found=%v", role, found)
	}
	if _, found := service.PublishedRoleDefinition(t.Context(), "missing"); found {
		t.Fatal("missing role was reported as published")
	}
}

func TestIdentityListAndEffectiveMenuFailureWindows(t *testing.T) {
	role := identitymodel.IdentityRole{ID: "role", Status: identitymodel.IdentityStatusActive}
	for _, test := range []struct {
		name       string
		repository *identityPermissionMenuRepository
	}{
		{name: "role assignments", repository: &identityPermissionMenuRepository{roleAssignmentErr: errIdentityDepartmentUserEdge}},
		{name: "roles", repository: &identityPermissionMenuRepository{roleAssignments: []identitymodel.IdentityUserRoleAssignment{{RoleID: role.ID}}, roleErr: errIdentityDepartmentUserEdge}},
		{name: "menus", repository: &identityPermissionMenuRepository{roleAssignments: []identitymodel.IdentityUserRoleAssignment{{RoleID: role.ID}}, roles: []identitymodel.IdentityRole{role}, menuErr: errIdentityDepartmentUserEdge}},
		{name: "menu assignments", repository: &identityPermissionMenuRepository{roleAssignments: []identitymodel.IdentityUserRoleAssignment{{RoleID: role.ID}}, roles: []identitymodel.IdentityRole{role}, menuAssignmentErr: errIdentityDepartmentUserEdge}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := identityPermissionMenuService(test.repository).EffectiveMenus(t.Context(), "user"); !errors.Is(err, errIdentityDepartmentUserEdge) {
				t.Fatalf("error=%v", err)
			}
		})
	}

	repository := &identityPermissionMenuRepository{menuErr: errIdentityDepartmentUserEdge}
	service := identityPermissionMenuService(repository)
	if _, err := service.ListMenus(t.Context()); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("list menus error=%v", err)
	}
	repository.menuErr = nil
	repository.menus = []identitymodel.IdentityMenu{{ID: "root"}}
	if values, err := service.ListMenus(t.Context()); err != nil || len(values) != 1 {
		t.Fatalf("menus=%+v err=%v", values, err)
	}
	if values, err := service.EffectiveMenus(t.Context(), " "); err != nil || len(values) != 0 {
		t.Fatalf("blank user menus=%+v err=%v", values, err)
	}
	repository.roleAssignments = nil
	if values, err := service.EffectiveMenus(t.Context(), "user"); err != nil || len(values) != 0 {
		t.Fatalf("roleless menus=%+v err=%v", values, err)
	}
}

func TestIdentityEffectiveMenusVisibilityParentAndSortEdges(t *testing.T) {
	role := identitymodel.IdentityRole{ID: "role", Status: identitymodel.IdentityStatusActive}
	repository := &identityPermissionMenuRepository{
		roleAssignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: role.ID}},
		roles:           []identitymodel.IdentityRole{role, {ID: "disabled-role", Status: identitymodel.IdentityStatusDisabled}},
		menus: []identitymodel.IdentityMenu{
			{ID: "root", Key: "root", Status: identitymodel.IdentityStatusActive, SortOrder: 2},
			{ID: "child", Key: "child", ParentID: "root", SortOrder: 1},
			{ID: "sibling", Key: "sibling", ParentID: "missing-parent", Status: identitymodel.IdentityStatusActive, SortOrder: 1},
			{ID: "self", Key: "self", ParentID: "self", Status: identitymodel.IdentityStatusActive, SortOrder: 3},
			{ID: "blank-key", Key: "", Status: identitymodel.IdentityStatusActive, SortOrder: 4},
			{ID: "disabled", Key: "disabled", Status: identitymodel.IdentityStatusDisabled},
			{ID: "", Key: "key-only", Status: identitymodel.IdentityStatusActive},
		},
		menuAssignments: []identitymodel.IdentityRoleMenuAssignment{
			{RoleID: role.ID, MenuID: "child"},
			{RoleID: role.ID, MenuID: "root"},
			{RoleID: role.ID, MenuID: "root"},
			{RoleID: role.ID, MenuID: "sibling"},
			{RoleID: role.ID, MenuID: "self"},
			{RoleID: role.ID, MenuID: "missing"},
			{RoleID: role.ID, MenuID: "key-only"},
			{RoleID: role.ID, MenuID: "disabled"},
		},
	}
	menus, err := identityPermissionMenuService(repository).EffectiveMenus(t.Context(), "user")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sibling", "root", "child", "self"}
	got := make([]string, 0, len(menus))
	for _, menu := range menus {
		got = append(got, menu.ID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("menu IDs=%v want=%v menus=%+v", got, want, menus)
	}
}

func TestIdentityEffectiveMenusOrdersCyclicLeftoversOnce(t *testing.T) {
	role := identitymodel.IdentityRole{ID: "role", Status: identitymodel.IdentityStatusActive}
	repository := &identityPermissionMenuRepository{
		roleAssignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: role.ID}},
		roles:           []identitymodel.IdentityRole{role},
		menus: []identitymodel.IdentityMenu{
			{ID: "cycle-a", Key: "a", ParentID: "cycle-b", Status: identitymodel.IdentityStatusActive, SortOrder: 1},
			{ID: "cycle-b", Key: "b", ParentID: "cycle-a", Status: identitymodel.IdentityStatusActive, SortOrder: 1},
		},
		menuAssignments: []identitymodel.IdentityRoleMenuAssignment{{RoleID: role.ID, MenuID: "cycle-a"}},
	}
	menus, err := identityPermissionMenuService(repository).EffectiveMenus(t.Context(), "user")
	if err != nil || len(menus) != 2 || menus[0].ID == menus[1].ID {
		t.Fatalf("menus=%+v error=%v", menus, err)
	}
}
