package service

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type identityPermissionMenuRepository struct {
	identityrepository.IdentityRepository
	roles             []identitymodel.IdentityRole
	roleAssignments   []identitymodel.IdentityUserRoleAssignment
	menus             []identitymodel.IdentityMenu
	permissionValues  []identitymodel.IdentityRolePermissionAssignment
	dataScopeValues   []identitymodel.IdentityDataScopePolicy
	fieldValues       []identitymodel.IdentityFieldPermission
	menuAssignments   []identitymodel.IdentityRoleMenuAssignment
	roleErr           error
	roleAssignmentErr error
	menuErr           error
	upsertMenuErr     error
	setRoleMenusErr   error
	permissionListErr error
	dataScopeListErr  error
	fieldListErr      error
	menuAssignmentErr error
	upsertedMenu      identitymodel.IdentityMenu
	setRoleMenuIDs    []string
}

func TestPublishedRoleAuthorizationReadsUsePublishedRoleSchema(t *testing.T) {
	role := identitymodel.IdentityRole{ID: "role", Key: "role", Status: identitymodel.IdentityStatusActive}
	repository := &identityPermissionMenuRepository{roles: []identitymodel.IdentityRole{role}}
	service := identityPermissionMenuService(repository)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "role", Permissions: []string{"record.read"},
		DataPermissions:  []identitymodel.DataPermission{{ObjectKey: "record", Scope: "owned"}},
		FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "record", FieldKey: "name", Read: true, Masked: true}},
	}})
	permissions, permissionErr := service.ListRolePermissionAssignments(t.Context(), "role")
	scopes, scopeErr := service.ListRoleDataScopes(t.Context(), "role")
	fields, fieldErr := service.ListRoleFieldPermissions(t.Context(), "role")
	if permissionErr != nil || scopeErr != nil || fieldErr != nil || len(permissions) != 1 || permissions[0].PermissionKey != "record.read" || len(scopes) != 1 || scopes[0].Scope != identitymodel.IdentityDataScope("owned") || len(fields) != 1 || !fields[0].Visible || !fields[0].Masked {
		t.Fatalf("published role reads permissions=%#v scopes=%#v fields=%#v errors=%v/%v/%v", permissions, scopes, fields, permissionErr, scopeErr, fieldErr)
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "role", Permissions: []string{" ", "record.read"},
		DataPermissions:  []identitymodel.DataPermission{{ObjectKey: " "}, {ObjectKey: "record"}},
		FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: " ", FieldKey: "name"}, {ObjectKey: "record", FieldKey: " "}, {ObjectKey: "record", FieldKey: "name", Read: true}},
	}})
	if values, err := service.ListRolePermissionAssignments(t.Context(), "role"); err != nil || len(values) != 1 {
		t.Fatalf("filtered permissions=%+v err=%v", values, err)
	}
	if values, err := service.ListRoleDataScopes(t.Context(), "role"); err != nil || len(values) != 1 {
		t.Fatalf("filtered scopes=%+v err=%v", values, err)
	}
	if values, err := service.ListRoleFieldPermissions(t.Context(), "role"); err != nil || len(values) != 1 {
		t.Fatalf("filtered fields=%+v err=%v", values, err)
	}
	repository.roleErr = errors.New("roles")
	for _, read := range []func() error{
		func() error { _, err := service.ListRolePermissionAssignments(t.Context(), "role"); return err },
		func() error { _, err := service.ListRoleDataScopes(t.Context(), "role"); return err },
		func() error { _, err := service.ListRoleFieldPermissions(t.Context(), "role"); return err },
	} {
		if err := read(); !errors.Is(err, repository.roleErr) {
			t.Fatalf("role read error=%v", err)
		}
	}
}

func (r *identityPermissionMenuRepository) ListIdentityRoles(context.Context, string) ([]identitymodel.IdentityRole, error) {
	return append([]identitymodel.IdentityRole(nil), r.roles...), r.roleErr
}
func (r *identityPermissionMenuRepository) ListIdentityUserRoleAssignments(context.Context, string, string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return append([]identitymodel.IdentityUserRoleAssignment(nil), r.roleAssignments...), r.roleAssignmentErr
}
func (r *identityPermissionMenuRepository) ListIdentityMenus(context.Context, string) ([]identitymodel.IdentityMenu, error) {
	return append([]identitymodel.IdentityMenu(nil), r.menus...), r.menuErr
}
func (r *identityPermissionMenuRepository) UpsertIdentityMenu(_ context.Context, _ string, value identitymodel.IdentityMenu) error {
	r.upsertedMenu = value
	return r.upsertMenuErr
}
func (r *identityPermissionMenuRepository) SetIdentityRoleMenus(_ context.Context, _, _ string, values []string) error {
	r.setRoleMenuIDs = append([]string(nil), values...)
	return r.setRoleMenusErr
}
func (r *identityPermissionMenuRepository) ListIdentityRolePermissionAssignments(context.Context, string, string) ([]identitymodel.IdentityRolePermissionAssignment, error) {
	return r.permissionValues, r.permissionListErr
}
func (r *identityPermissionMenuRepository) ListIdentityRoleDataScopes(context.Context, string, string) ([]identitymodel.IdentityDataScopePolicy, error) {
	return r.dataScopeValues, r.dataScopeListErr
}
func (r *identityPermissionMenuRepository) ListIdentityRoleFieldPermissions(context.Context, string, string) ([]identitymodel.IdentityFieldPermission, error) {
	return r.fieldValues, r.fieldListErr
}
func (r *identityPermissionMenuRepository) ListIdentityRoleMenuAssignments(context.Context, string, string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return r.menuAssignments, r.menuAssignmentErr
}

type identityPermissionMenuAtomicRepository struct {
	*identityPermissionMenuRepository
	removeErr    error
	removedMenus []identitymodel.IdentityMenu
}

func (r *identityPermissionMenuAtomicRepository) RemoveIdentityMenusAtomically(_ context.Context, _ string, menus []identitymodel.IdentityMenu) error {
	r.removedMenus = append([]identitymodel.IdentityMenu(nil), menus...)
	return r.removeErr
}

func identityPermissionMenuService(repository identityrepository.IdentityRepository) *IdentityDomainService {
	service := NewIdentityDomainService(repository, []identitymodel.IdentityPermissionDefinition{{Key: "record.read"}, {Key: "record.write"}})
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "role", Name: "Role", RecordScope: "all_records"}})
	return service
}

func TestIdentityRoleAuthorizationListDelegates(t *testing.T) {
	repository := &identityPermissionMenuRepository{
		permissionValues:  []identitymodel.IdentityRolePermissionAssignment{{RoleID: "role", PermissionKey: "record.read"}},
		dataScopeValues:   []identitymodel.IdentityDataScopePolicy{{Resource: "record"}},
		fieldValues:       []identitymodel.IdentityFieldPermission{{Resource: "record", Field: "name"}},
		menuAssignments:   []identitymodel.IdentityRoleMenuAssignment{{RoleID: "role", MenuID: "root"}},
		permissionListErr: nil,
	}
	service := identityPermissionMenuService(repository)
	if values, err := service.ListRolePermissionAssignments(t.Context(), "role"); err != nil || len(values) != 0 {
		t.Fatalf("permissions=%+v err=%v", values, err)
	}
	if values, err := service.ListRoleDataScopes(t.Context(), "role"); err != nil || len(values) != 0 {
		t.Fatalf("scopes=%+v err=%v", values, err)
	}
	if values, err := service.ListRoleFieldPermissions(t.Context(), "role"); err != nil || len(values) != 0 {
		t.Fatalf("fields=%+v err=%v", values, err)
	}
	if values, err := service.ListRoleMenuAssignments(t.Context(), "role"); err != nil || len(values) != 1 {
		t.Fatalf("menus=%+v err=%v", values, err)
	}
}

func TestIdentityUpsertMenuValidationAndPersistenceEdges(t *testing.T) {
	root := identitymodel.IdentityMenu{ID: "root", Key: "root", Label: "Root", Status: identitymodel.IdentityStatusActive}
	child := identitymodel.IdentityMenu{ID: "child", Key: "child", Label: "Child", ParentID: "root", Status: identitymodel.IdentityStatusActive}
	for _, test := range []struct {
		name       string
		repository *identityPermissionMenuRepository
		menu       identitymodel.IdentityMenu
	}{
		{name: "empty", repository: &identityPermissionMenuRepository{}, menu: identitymodel.IdentityMenu{}},
		{name: "list", repository: &identityPermissionMenuRepository{menuErr: errIdentityOrganizationUnitUserEdge}, menu: root},
		{name: "duplicate-key", repository: &identityPermissionMenuRepository{menus: []identitymodel.IdentityMenu{{ID: "other", Key: "ROOT"}}}, menu: root},
		{name: "self-parent", repository: &identityPermissionMenuRepository{}, menu: identitymodel.IdentityMenu{ID: "root", Key: "root", ParentID: "root"}},
		{name: "missing-parent", repository: &identityPermissionMenuRepository{}, menu: child},
		{name: "cycle", repository: &identityPermissionMenuRepository{menus: []identitymodel.IdentityMenu{root, {ID: "parent", Key: "parent", ParentID: "child"}}}, menu: identitymodel.IdentityMenu{ID: "child", Key: "child", ParentID: "parent"}},
		{name: "broken-ancestor", repository: &identityPermissionMenuRepository{menus: []identitymodel.IdentityMenu{{ID: "parent", Key: "parent", ParentID: "missing"}}}, menu: identitymodel.IdentityMenu{ID: "child", Key: "child", ParentID: "parent"}},
		{name: "write", repository: &identityPermissionMenuRepository{upsertMenuErr: errIdentityOrganizationUnitUserEdge}, menu: root},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := identityPermissionMenuService(test.repository).UpsertMenu(t.Context(), test.menu); err == nil {
				t.Fatal("invalid menu was accepted")
			}
		})
	}

	for _, menu := range []identitymodel.IdentityMenu{{Key: "key-only"}, {ID: "id-only"}, {ID: "full", Key: "full", Label: "Label", Status: identitymodel.IdentityStatusDisabled}} {
		repository := &identityPermissionMenuRepository{}
		if err := identityPermissionMenuService(repository).UpsertMenu(t.Context(), menu); err != nil {
			t.Fatal(err)
		}
		if repository.upsertedMenu.ID == "" || repository.upsertedMenu.Key == "" || repository.upsertedMenu.Label == "" || repository.upsertedMenu.Status == "" {
			t.Fatalf("upserted menu=%+v", repository.upsertedMenu)
		}
	}
	repository := &identityPermissionMenuRepository{menus: []identitymodel.IdentityMenu{root}}
	if err := identityPermissionMenuService(repository).UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "child", Key: "child", ParentID: "root"}); err != nil {
		t.Fatal(err)
	}
	repository = &identityPermissionMenuRepository{menus: []identitymodel.IdentityMenu{{ID: "same", Key: "old"}}}
	if err := identityPermissionMenuService(repository).UpsertMenu(t.Context(), identitymodel.IdentityMenu{ID: "same", Key: "new"}); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityMenuParentNoLongerCarriesProductSurface(t *testing.T) {
	parent := identitymodel.IdentityMenu{
		ID: "admin-root", Key: "admin-root",
	}
	repository := &identityPermissionMenuRepository{menus: []identitymodel.IdentityMenu{parent}}
	err := identityPermissionMenuService(repository).UpsertMenu(t.Context(), identitymodel.IdentityMenu{
		ID: "ops-child", Key: "ops-child", ParentID: parent.ID,
	})
	if err != nil {
		t.Fatalf("single-shell parent rejected: %v", err)
	}
}

func TestIdentityRemoveAndAssignMenusEdges(t *testing.T) {
	root := identitymodel.IdentityMenu{ID: "root", Key: "root"}
	child := identitymodel.IdentityMenu{ID: "child", Key: "child-key", ParentID: "root"}
	grandchild := identitymodel.IdentityMenu{ID: "grandchild", Key: "grandchild", ParentID: "child"}
	role := identitymodel.IdentityRole{ID: "role"}

	for _, test := range []struct {
		name       string
		repository identityrepository.IdentityRepository
		menuID     string
	}{
		{name: "list", repository: &identityPermissionMenuRepository{menuErr: errIdentityOrganizationUnitUserEdge}, menuID: "root"},
		{name: "missing", repository: &identityPermissionMenuRepository{}, menuID: "root"},
		{name: "non-atomic", repository: &identityPermissionMenuRepository{menus: []identitymodel.IdentityMenu{root}}, menuID: "root"},
	} {
		t.Run("remove-"+test.name, func(t *testing.T) {
			if _, err := identityPermissionMenuService(test.repository).RemoveMenu(t.Context(), test.menuID); err == nil {
				t.Fatal("remove failure window was accepted")
			}
		})
	}

	base := &identityPermissionMenuRepository{menus: []identitymodel.IdentityMenu{root, child, grandchild}}
	atomic := &identityPermissionMenuAtomicRepository{identityPermissionMenuRepository: base}
	service := identityPermissionMenuService(atomic)
	deleted, err := service.RemoveMenu(t.Context(), "root")
	if err != nil || !reflect.DeepEqual(deleted, []string{"grandchild", "child", "root"}) {
		t.Fatalf("deleted=%v err=%v", deleted, err)
	}
	atomic.removeErr = errIdentityOrganizationUnitUserEdge
	if _, err := service.RemoveMenu(t.Context(), "root"); !errors.Is(err, errIdentityOrganizationUnitUserEdge) {
		t.Fatalf("remove error=%v", err)
	}
	atomic.removeErr = nil
	if deleted, err := service.RemoveMenu(t.Context(), " child-key "); err != nil || !reflect.DeepEqual(deleted, []string{"grandchild", "child"}) {
		t.Fatalf("key delete=%v err=%v", deleted, err)
	}

	for _, test := range []struct {
		name       string
		repository *identityPermissionMenuRepository
		menuIDs    []string
	}{
		{name: "role-read", repository: &identityPermissionMenuRepository{roleErr: errIdentityOrganizationUnitUserEdge}},
		{name: "role-missing", repository: &identityPermissionMenuRepository{}},
		{name: "menu-list", repository: &identityPermissionMenuRepository{roles: []identitymodel.IdentityRole{role}, menuErr: errIdentityOrganizationUnitUserEdge}},
		{name: "unknown", repository: &identityPermissionMenuRepository{roles: []identitymodel.IdentityRole{role}, menus: []identitymodel.IdentityMenu{root}}, menuIDs: []string{"missing"}},
		{name: "write", repository: &identityPermissionMenuRepository{roles: []identitymodel.IdentityRole{role}, menus: []identitymodel.IdentityMenu{root}, setRoleMenusErr: errIdentityOrganizationUnitUserEdge}, menuIDs: []string{"", "root"}},
	} {
		t.Run("assign-"+test.name, func(t *testing.T) {
			if err := identityPermissionMenuService(test.repository).SetRoleMenus(t.Context(), "role", test.menuIDs); err == nil {
				t.Fatal("role menu failure window was accepted")
			}
		})
	}
	repository := &identityPermissionMenuRepository{roles: []identitymodel.IdentityRole{role}, menus: []identitymodel.IdentityMenu{root}}
	if err := identityPermissionMenuService(repository).SetRoleMenus(t.Context(), "role", []string{" ", "root"}); err != nil || len(repository.setRoleMenuIDs) != 2 {
		t.Fatalf("assigned IDs=%v err=%v", repository.setRoleMenuIDs, err)
	}
}
