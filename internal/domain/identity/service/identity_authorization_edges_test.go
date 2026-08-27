package service

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityAuthorizationRepository struct {
	*identityPrincipalRoleRepository
	departments     []identitymodel.IdentityDepartment
	menus           []identitymodel.IdentityMenu
	menuAssignments []identitymodel.IdentityRoleMenuAssignment
	departmentsErr  error
}

func (r *identityAuthorizationRepository) ListIdentityDepartments(context.Context, string) ([]identitymodel.IdentityDepartment, error) {
	return append([]identitymodel.IdentityDepartment(nil), r.departments...), r.departmentsErr
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
		identityPrincipalRoleRepository: &identityPrincipalRoleRepository{
			identityRolesRepositoryStub: &identityRolesRepositoryStub{
				users:       []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
				roles:       []identitymodel.IdentityRole{role},
				assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "role"}},
			},
			permissionAssignments: []identitymodel.IdentityRolePermissionAssignment{{RoleID: "role", PermissionKey: "record.read"}},
		},
		departments:     []identitymodel.IdentityDepartment{{ID: "department", Name: "Department", Status: identitymodel.IdentityStatusActive}},
		menus:           []identitymodel.IdentityMenu{{ID: "menu", Key: "menu", Status: identitymodel.IdentityStatusActive}},
		menuAssignments: []identitymodel.IdentityRoleMenuAssignment{{RoleID: "role", MenuID: "menu"}},
	}
	service := NewIdentityDomainService(repository, nil).mustForWorkspace(t, "workspace")
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "role", Permissions: []string{"record.read"}, RecordScope: "all_records"}})
	if assignments, workforceProfileID, err := service.ResolveEffectiveRoleAssignments(t.Context(), "user"); err != nil || len(assignments) != 1 || workforceProfileID != "" {
		t.Fatalf("effective assignments=%+v workforce=%q err=%v", assignments, workforceProfileID, err)
	}
	repository.assignments[0].Status = "revoked"
	if assignments, _, err := service.ResolveEffectiveRoleAssignments(t.Context(), "user"); err != nil || len(assignments) != 0 {
		t.Fatalf("inactive assignments=%+v err=%v", assignments, err)
	}
	repository.assignments[0].Status = ""
	repository.workforceProfilesErr = errors.New("workforce")
	if _, _, err := service.ResolveEffectiveRoleAssignments(t.Context(), "user"); !errors.Is(err, repository.workforceProfilesErr) {
		t.Fatalf("workforce error=%v", err)
	}
	repository.workforceProfilesErr = nil
	repository.listAssignmentsErr = errors.New("assignments")
	if _, _, err := service.ResolveEffectiveRoleAssignments(t.Context(), "user"); !errors.Is(err, repository.listAssignmentsErr) {
		t.Fatalf("assignments error=%v", err)
	}
	repository.listAssignmentsErr = nil
	repository.assignments[0].BindingKey, repository.assignments[0].ProfileID = "member", "profile"
	bindingErr := errors.New("binding")
	service.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{err: bindingErr})
	if _, _, err := service.ResolveEffectiveRoleAssignments(t.Context(), "user"); !errors.Is(err, bindingErr) {
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
	if department, found, err := service.FindDepartment(t.Context(), "department"); err != nil || !found || department.ID != "department" {
		t.Fatalf("department=%+v found=%v err=%v", department, found, err)
	}
	if _, found, err := service.FindDepartment(t.Context(), "missing"); err != nil || found {
		t.Fatalf("missing department found=%v err=%v", found, err)
	}
	repository.departmentsErr = errors.New("departments")
	if _, _, err := service.FindDepartment(t.Context(), "department"); !errors.Is(err, repository.departmentsErr) {
		t.Fatalf("department error=%v", err)
	}
	repository.departmentsErr = nil
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
		func() error { _, _, err := service.FindDepartment(cancelled, "department"); return err },
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

func (s *IdentityDomainService) mustForWorkspace(t *testing.T, workspace string) *IdentityDomainService {
	t.Helper()
	scoped, err := s.ForWorkspace(workspace)
	if err != nil {
		t.Fatal(err)
	}
	return scoped
}
