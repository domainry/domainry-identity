package service

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityAuthorizationRepository struct {
	*identityRolesRepositoryStub
	organizationUnits     []identitymodel.IdentityOrganizationUnit
	menus                 []identitymodel.IdentityMenu
	menuAssignments       []identitymodel.IdentityRoleMenuAssignment
	permissionAssignments []identitymodel.IdentityRolePermissionAssignment
	organizationUnitsErr  error
}

type identityRoleBindingEligibilityStub struct{ err error }

func (s identityRoleBindingEligibilityStub) IdentityRoleBindingActive(context.Context, string, string, string, string) (bool, error) {
	return s.err == nil, s.err
}

func activateIdentityTestPermissions(service *IdentityDomainService, keys ...string) {
	definitions := make([]identitymodel.IdentityPermissionDefinition, 0, len(keys))
	for _, key := range keys {
		definitions = append(definitions, identitymodel.IdentityPermissionDefinition{Key: key, DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true})
	}
	service.ReplacePermissionDefinitions(definitions)
}

func identityTestRolePermissions(keys ...string) []identitymodel.RolePermission {
	return identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, keys...)
}

func identityTestScopedRolePermissions(scope identitymodel.IdentityDataScope, keys ...string) []identitymodel.RolePermission {
	return identitymodel.RolePermissionsWithScope(scope, keys...)
}

func TestIdentityPrincipalWithoutRolesHasNoImplicitManagementScope(t *testing.T) {
	repository := &identityAuthorizationRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{
		users: []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
	}}
	principal, err := NewIdentityDomainService(repository, nil).mustForWorkspace(t, "workspace").ResolvePrincipal(t.Context(), "user")
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Known || len(principal.Role.Permissions) != 0 {
		t.Fatalf("principal gained implicit management scope: %+v", principal)
	}
}

func TestIdentityActorUsesPermissionDataScopeForRoleAssignmentTarget(t *testing.T) {
	actor := identitymodel.Principal{
		Known: true, UserID: "manager", OrgID: "sales",
		SupportOrgScopeIDs: []string{"sales", "sales-east"},
		Role:               identitymodel.RoleSchema{Permissions: identityTestScopedRolePermissions(identitymodel.IdentityDataScopeTargetOrg, identitycontract.IdentityUserRoleAssignmentsAssignPermission)},
	}
	for _, target := range []identitymodel.IdentityUser{{ID: "peer", OrgID: "sales"}, {ID: "east", OrgID: "sales-east"}} {
		if !identitycontract.IdentityPermissionDataScopeAllows(actor, identitycontract.IdentityUserRoleAssignmentsAssignPermission, identitycontract.IdentityResourceFacts{RecordID: target.ID, OwnerUserID: target.ID, OwnerOrgID: target.OrgID}) {
			t.Fatalf("explicit management scope rejected target %+v", target)
		}
	}
	if identitycontract.IdentityPermissionDataScopeAllows(actor, identitycontract.IdentityUserRoleAssignmentsAssignPermission, identitycontract.IdentityResourceFacts{RecordID: "outsider", OwnerUserID: "outsider", OwnerOrgID: "other"}) {
		t.Fatal("explicit management scopes expanded to an unrelated target")
	}
}

func (r *identityAuthorizationRepository) ListIdentityRolePermissionAssignments(context.Context, string, string) ([]identitymodel.IdentityRolePermissionAssignment, error) {
	return append([]identitymodel.IdentityRolePermissionAssignment(nil), r.permissionAssignments...), nil
}

func (r *identityAuthorizationRepository) ListIdentityRoleFieldPermissions(context.Context, string, string) ([]identitymodel.IdentityFieldPermission, error) {
	return nil, nil
}

func (r *identityAuthorizationRepository) ListIdentityOrganizationUnits(context.Context, string) ([]identitymodel.IdentityOrganizationUnit, error) {
	return append([]identitymodel.IdentityOrganizationUnit(nil), r.organizationUnits...), r.organizationUnitsErr
}

func (r *identityAuthorizationRepository) ListIdentityMenus(context.Context, string) ([]identitymodel.IdentityMenu, error) {
	return append([]identitymodel.IdentityMenu(nil), r.menus...), nil
}

func (r *identityAuthorizationRepository) ListIdentityRoleMenuAssignments(context.Context, string, string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return append([]identitymodel.IdentityRoleMenuAssignment(nil), r.menuAssignments...), nil
}

func TestIdentityAuthorizationContextBoundaryAndDelegation(t *testing.T) {
	role := identitymodel.IdentityRole{ID: "role", Key: "role", Status: identitymodel.IdentityStatusActive}
	repository := &identityAuthorizationRepository{
		identityRolesRepositoryStub: &identityRolesRepositoryStub{
			users:       []identitymodel.IdentityUser{{ID: "user", OrgID: "sales", Status: identitymodel.IdentityStatusActive}},
			roles:       []identitymodel.IdentityRole{role},
			assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "role"}},
		},
		permissionAssignments: []identitymodel.IdentityRolePermissionAssignment{{RoleID: "role", PermissionKey: "record.read"}},
		organizationUnits:     []identitymodel.IdentityOrganizationUnit{{ID: "sales", Name: "Sales", Path: "/company/sales", Status: identitymodel.IdentityStatusActive}},
		menus:                 []identitymodel.IdentityMenu{{ID: "menu", Key: "menu", Status: identitymodel.IdentityStatusActive}},
		menuAssignments:       []identitymodel.IdentityRoleMenuAssignment{{RoleID: "role", MenuID: "menu"}},
	}
	service := NewIdentityDomainService(repository, nil).mustForWorkspace(t, "workspace")
	activateIdentityTestPermissions(service, "record.read")
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "role", Permissions: identityTestRolePermissions("record.read")}})
	if assignments, err := service.ResolveEffectiveRoleAssignments(t.Context(), "user"); err != nil || len(assignments) != 1 {
		t.Fatalf("effective assignments=%+v err=%v", assignments, err)
	}
	repository.assignments[0].Status = "revoked"
	if assignments, err := service.ResolveEffectiveRoleAssignments(t.Context(), "user"); err != nil || len(assignments) != 0 {
		t.Fatalf("inactive assignments=%+v err=%v", assignments, err)
	}
	repository.assignments[0].Status = ""
	repository.listAssignmentsErr = errors.New("assignments")
	if _, err := service.ResolveEffectiveRoleAssignments(t.Context(), "user"); !errors.Is(err, repository.listAssignmentsErr) {
		t.Fatalf("assignments error=%v", err)
	}
	repository.listAssignmentsErr = nil
	repository.assignments[0].BindingKey, repository.assignments[0].ProfileID = "member", "profile"
	bindingErr := errors.New("binding")
	service.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{err: bindingErr})
	if _, err := service.ResolveEffectiveRoleAssignments(t.Context(), "user"); !errors.Is(err, bindingErr) {
		t.Fatalf("binding error=%v", err)
	}
	service.UseRoleBindingEligibility(nil)
	repository.assignments[0].BindingKey, repository.assignments[0].ProfileID = "", ""

	if principal, err := service.ResolvePrincipal(t.Context(), "user"); err != nil || !principal.Known {
		t.Fatalf("principal=%+v err=%v", principal, err)
	}
	if principal, err := service.ResolvePrincipalForRole(t.Context(), "user", "role"); err != nil || !principal.Known || principal.Role.Key != "role" {
		t.Fatalf("role principal=%+v err=%v", principal, err)
	}
	if permissions, err := service.ResolveEffectivePermissions(t.Context(), "user"); err != nil || !reflect.DeepEqual(permissions, []string{"record.read"}) {
		t.Fatalf("permissions=%v err=%v", permissions, err)
	}
	if menus, err := service.ResolveEffectiveMenus(t.Context(), "user"); err != nil || len(menus) != 1 || menus[0].ID != "menu" {
		t.Fatalf("menus=%+v err=%v", menus, err)
	}
	if user, found, err := service.FindUser(t.Context(), "user"); err != nil || !found || user.ID != "user" {
		t.Fatalf("user=%+v found=%v err=%v", user, found, err)
	}
	if organizationUnit, found, err := service.FindOrganizationUnit(t.Context(), "sales"); err != nil || !found || organizationUnit.ID != "sales" {
		t.Fatalf("organizationUnit=%+v found=%v err=%v", organizationUnit, found, err)
	}
	if _, found, err := service.FindOrganizationUnit(t.Context(), "missing"); err != nil || found {
		t.Fatalf("missing organizationUnit found=%v err=%v", found, err)
	}
	repository.organizationUnitsErr = errors.New("organizationUnits")
	if _, _, err := service.FindOrganizationUnit(t.Context(), "sales"); !errors.Is(err, repository.organizationUnitsErr) {
		t.Fatalf("organizationUnit error=%v", err)
	}
	repository.organizationUnitsErr = nil
	if users, err := service.ListDirectoryUsers(t.Context()); err != nil || len(users) != 1 {
		t.Fatalf("users=%+v err=%v", users, err)
	}
	if roles, err := service.ListDirectoryRoles(t.Context()); err != nil || len(roles) != 1 {
		t.Fatalf("roles=%+v err=%v", roles, err)
	}
	if assignments, err := service.ListDirectoryUserRoleAssignments(t.Context(), "user"); err != nil || len(assignments) != 1 {
		t.Fatalf("assignments=%+v err=%v", assignments, err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	checks := []func() error{
		func() error { _, err := service.ResolvePrincipal(cancelled, "user"); return err },
		func() error { _, err := service.ResolvePrincipalForRole(cancelled, "user", "role"); return err },
		func() error { _, err := service.ResolveEffectivePermissions(cancelled, "user"); return err },
		func() error { _, err := service.ResolveEffectiveMenus(cancelled, "user"); return err },
		func() error { _, _, err := service.FindUser(cancelled, "user"); return err },
		func() error { _, _, err := service.FindOrganizationUnit(cancelled, "sales"); return err },
		func() error { _, err := service.ListDirectoryUsers(cancelled); return err },
		func() error { _, err := service.ListDirectoryRoles(cancelled); return err },
		func() error { _, err := service.ListDirectoryUserRoleAssignments(cancelled, "user"); return err },
	}
	for index, check := range checks {
		if err := check(); !errors.Is(err, context.Canceled) {
			t.Fatalf("check %d error=%v", index, err)
		}
	}
}

func TestIdentityPrincipalResolutionNeverDefaultsAnEmptySubjectToAdmin(t *testing.T) {
	repository := &identityAuthorizationRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{
		users: []identitymodel.IdentityUser{{ID: "admin", Status: identitymodel.IdentityStatusActive}},
	}}
	service := NewIdentityDomainService(repository, nil).mustForWorkspace(t, "workspace")
	for _, resolve := range []func() (identitymodel.Principal, error){
		func() (identitymodel.Principal, error) { return service.ResolvePrincipal(t.Context(), "") },
		func() (identitymodel.Principal, error) {
			return service.ResolvePrincipalForRole(t.Context(), "", "admin")
		},
	} {
		principal, err := resolve()
		if err != nil || principal.Known || principal.UserID != "" {
			t.Fatalf("empty subject principal=%+v err=%v", principal, err)
		}
	}
}

func (s *IdentityDomainService) mustForWorkspace(t *testing.T, workspace string) *IdentityDomainService {
	t.Helper()
	scoped, err := s.ForWorkspace(workspace)
	if err != nil {
		t.Fatal(err)
	}
	return scoped
}
