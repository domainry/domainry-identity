package identity_test

import (
	"errors"
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityStoreWorkspaceIsolationContract(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		assertIdentityRepositoryWorkspaceIsolation(t, identitypersistence.NewMemoryIdentityStore())
	})
	t.Run("sql", func(t *testing.T) {
		store, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-workspace.db")})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if err := store.EnsureSchema(t.Context()); err != nil {
			t.Fatal(err)
		}
		repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
		if err != nil {
			t.Fatal(err)
		}
		assertIdentityRepositoryWorkspaceIsolation(t, repository)
	})
}

type identityWorkspaceRepository interface {
	identityrepository.IdentityRepository
	identityrepository.IdentityWorkforceRepository
}

func assertIdentityRepositoryWorkspaceIsolation(t *testing.T, repository identityWorkspaceRepository) {
	t.Helper()
	ctx := t.Context()
	const workspaceA, workspaceB = "workspace-a", "workspace-b"
	departmentA := identitymodel.IdentityDepartment{ID: "department-a", Name: "Department A", Path: "/department-a"}
	departmentB := identitymodel.IdentityDepartment{ID: "department-b", Name: "Department B", Path: "/department-b"}
	userA := identitymodel.IdentityUser{ID: "user-a", Name: "User A", Email: "a@example.com"}
	userB := identitymodel.IdentityUser{ID: "user-b", Name: "User B", Email: "b@example.com"}
	workforceA := identitymodel.IdentityWorkforceProfile{ID: "workforce-a", OrganizationID: "organization-a", IdentityUserID: userA.ID, WorkerNo: "A-001", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive}
	workforceB := identitymodel.IdentityWorkforceProfile{ID: "workforce-b", OrganizationID: "organization-b", IdentityUserID: userB.ID, WorkerNo: "B-001", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive}
	workforceAssignmentA := identitymodel.IdentityWorkforceAssignment{ID: "workforce-assignment-a", WorkforceProfileID: workforceA.ID, OrganizationUnitID: departmentA.ID, AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive}
	workforceAssignmentB := identitymodel.IdentityWorkforceAssignment{ID: "workforce-assignment-b", WorkforceProfileID: workforceB.ID, OrganizationUnitID: departmentB.ID, AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive}
	roleA := identitymodel.IdentityRole{ID: "role-a", Key: "role-a", Label: "Role A"}
	roleB := identitymodel.IdentityRole{ID: "role-b", Key: "role-b", Label: "Role B"}
	menuA := identitymodel.IdentityMenu{ID: "menu-a", Key: "menu-a", Label: "Menu A"}
	menuB := identitymodel.IdentityMenu{ID: "menu-b", Key: "menu-b", Label: "Menu B"}

	for _, seed := range []func() error{
		func() error { return repository.UpsertIdentityDepartment(ctx, workspaceA, departmentA) },
		func() error { return repository.UpsertIdentityDepartment(ctx, workspaceB, departmentB) },
		func() error { return repository.UpsertIdentityUser(ctx, workspaceA, userA) },
		func() error { return repository.UpsertIdentityUser(ctx, workspaceB, userB) },
		func() error { return repository.UpsertIdentityWorkforceProfile(ctx, workspaceA, workforceA) },
		func() error { return repository.UpsertIdentityWorkforceProfile(ctx, workspaceB, workforceB) },
		func() error {
			return repository.UpsertIdentityWorkforceAssignment(ctx, workspaceA, workforceAssignmentA)
		},
		func() error {
			return repository.UpsertIdentityWorkforceAssignment(ctx, workspaceB, workforceAssignmentB)
		},
		func() error { return repository.UpsertIdentityRole(ctx, workspaceA, roleA) },
		func() error { return repository.UpsertIdentityRole(ctx, workspaceB, roleB) },
		func() error {
			return repository.AssignIdentityUserRole(ctx, workspaceA, identitymodel.IdentityUserRoleAssignment{UserID: userA.ID, RoleID: roleA.ID})
		},
		func() error {
			return repository.AssignIdentityUserRole(ctx, workspaceB, identitymodel.IdentityUserRoleAssignment{UserID: userB.ID, RoleID: roleB.ID})
		},
		func() error { return repository.UpsertIdentityMenu(ctx, workspaceA, menuA) },
		func() error { return repository.UpsertIdentityMenu(ctx, workspaceB, menuB) },
		func() error { return repository.SetIdentityRoleMenus(ctx, workspaceA, roleA.ID, []string{menuA.ID}) },
		func() error { return repository.SetIdentityRoleMenus(ctx, workspaceB, roleB.ID, []string{menuB.ID}) },
	} {
		if err := seed(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repository.CreateIdentityRoleRequest(ctx, workspaceA, identitymodel.IdentityRoleRequest{ID: "request-a", UserID: userA.ID, RoleIDs: []string{roleA.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateIdentityRoleRequest(ctx, workspaceB, identitymodel.IdentityRoleRequest{ID: "request-b", UserID: userB.ID, RoleIDs: []string{roleB.ID}}); err != nil {
		t.Fatal(err)
	}

	departments, _ := repository.ListIdentityDepartments(ctx, workspaceA)
	users, _ := repository.ListIdentityUsers(ctx, workspaceA)
	workforceProfiles, _ := repository.ListIdentityWorkforceProfiles(ctx, workspaceA)
	workforceAssignments, _ := repository.ListIdentityWorkforceAssignments(ctx, workspaceA, workforceA.ID)
	roles, _ := repository.ListIdentityRoles(ctx, workspaceA)
	assignments, _ := repository.ListIdentityUserRoleAssignments(ctx, workspaceA, "")
	menus, _ := repository.ListIdentityMenus(ctx, workspaceA)
	roleMenus, _ := repository.ListIdentityRoleMenuAssignments(ctx, workspaceA, "")
	requests, _ := repository.ListIdentityRoleRequests(ctx, workspaceA, "", "")
	if len(departments) != 1 || departments[0].ID != departmentA.ID ||
		len(users) != 1 || users[0].ID != userA.ID ||
		len(workforceProfiles) != 1 || workforceProfiles[0].ID != workforceA.ID ||
		len(workforceAssignments) != 1 || workforceAssignments[0].ID != workforceAssignmentA.ID ||
		len(roles) != 1 || roles[0].ID != roleA.ID ||
		len(assignments) != 1 || assignments[0].UserID != userA.ID ||
		len(menus) != 1 || menus[0].ID != menuA.ID ||
		len(roleMenus) != 1 || roleMenus[0].MenuID != menuA.ID ||
		len(requests) != 1 || requests[0].ID != "request-a" {
		t.Fatalf("workspace A leaked or lost data: departments=%#v users=%#v workforceProfiles=%#v workforceAssignments=%#v roles=%#v assignments=%#v menus=%#v roleMenus=%#v requests=%#v", departments, users, workforceProfiles, workforceAssignments, roles, assignments, menus, roleMenus, requests)
	}
	if _, found, err := repository.GetIdentityUser(ctx, workspaceB, userA.ID); err != nil || found {
		t.Fatalf("workspace B read workspace A user: found=%v err=%v", found, err)
	}
	if _, found, err := repository.GetIdentityWorkforceProfile(ctx, workspaceB, workforceA.ID); err != nil || found {
		t.Fatalf("workspace B read workspace A Workforce Profile: found=%v err=%v", found, err)
	}
	if _, found, err := repository.GetIdentityWorkforceAssignment(ctx, workspaceB, workforceAssignmentA.ID); err != nil || found {
		t.Fatalf("workspace B read workspace A Workforce Assignment: found=%v err=%v", found, err)
	}
	_ = repository.SetIdentityUserStatus(ctx, workspaceB, userA.ID, identitymodel.IdentityStatusDisabled)
	storedA, found, err := repository.GetIdentityUser(ctx, workspaceA, userA.ID)
	if err != nil || !found || storedA.Status != identitymodel.IdentityStatusActive {
		t.Fatalf("cross-workspace status mutation changed A: user=%#v found=%v err=%v", storedA, found, err)
	}

	assertIdentityRepositoryRejectsMissingWorkspace(t, repository)
}

func assertIdentityRepositoryRejectsMissingWorkspace(t *testing.T, repository identityWorkspaceRepository) {
	t.Helper()
	ctx := t.Context()
	role := identitymodel.IdentityRole{ID: "missing-role"}
	menu := identitymodel.IdentityMenu{ID: "missing-menu"}
	atomic := repository.(identityrepository.IdentityAtomicMutationRepository)
	operations := []func() error{
		func() error { _, err := repository.ListIdentityDepartments(ctx, ""); return err },
		func() error {
			return repository.UpsertIdentityDepartment(ctx, "", identitymodel.IdentityDepartment{ID: "missing"})
		},
		func() error { _, err := repository.ListIdentityUsers(ctx, ""); return err },
		func() error { _, _, err := repository.GetIdentityUser(ctx, "", "user"); return err },
		func() error { return repository.UpsertIdentityUser(ctx, "", identitymodel.IdentityUser{ID: "user"}) },
		func() error { return repository.UpsertIdentityUsersAtomically(ctx, "", nil) },
		func() error { return repository.RemoveIdentityUser(ctx, "", "user") },
		func() error {
			return repository.SetIdentityUserStatus(ctx, "", "user", identitymodel.IdentityStatusDisabled)
		},
		func() error { _, err := repository.ListIdentityWorkforceProfiles(ctx, ""); return err },
		func() error { _, _, err := repository.GetIdentityWorkforceProfile(ctx, "", "workforce"); return err },
		func() error {
			return repository.UpsertIdentityWorkforceProfile(ctx, "", identitymodel.IdentityWorkforceProfile{ID: "workforce"})
		},
		func() error { _, err := repository.ListIdentityWorkforceAssignments(ctx, "", "workforce"); return err },
		func() error {
			_, _, err := repository.GetIdentityWorkforceAssignment(ctx, "", "assignment")
			return err
		},
		func() error {
			return repository.UpsertIdentityWorkforceAssignment(ctx, "", identitymodel.IdentityWorkforceAssignment{ID: "assignment"})
		},
		func() error { _, err := repository.ListIdentityRoles(ctx, ""); return err },
		func() error { return repository.UpsertIdentityRole(ctx, "", role) },
		func() error { return repository.RemoveIdentityRole(ctx, "", role.ID) },
		func() error {
			return repository.AssignIdentityUserRole(ctx, "", identitymodel.IdentityUserRoleAssignment{UserID: "user", RoleID: role.ID})
		},
		func() error { return repository.RemoveIdentityUserRole(ctx, "", "user", role.ID) },
		func() error { _, err := repository.ListIdentityUserRoleAssignments(ctx, "", "user"); return err },
		func() error {
			_, err := repository.CreateIdentityRoleRequest(ctx, "", identitymodel.IdentityRoleRequest{ID: "request"})
			return err
		},
		func() error { _, err := repository.ListIdentityRoleRequests(ctx, "", "", ""); return err },
		func() error {
			return repository.UpdateIdentityRoleRequest(ctx, "", identitymodel.IdentityRoleRequest{ID: "request"})
		},
		func() error { _, err := repository.ListIdentityMenus(ctx, ""); return err },
		func() error { return repository.UpsertIdentityMenu(ctx, "", menu) },
		func() error { return repository.RemoveIdentityMenu(ctx, "", menu.ID) },
		func() error { return repository.SetIdentityRoleMenus(ctx, "", role.ID, nil) },
		func() error { _, err := repository.ListIdentityRoleMenuAssignments(ctx, "", role.ID); return err },
		func() error { return atomic.RemoveIdentityMenusAtomically(ctx, "", []identitymodel.IdentityMenu{menu}) },
	}
	for index, operation := range operations {
		if err := operation(); !errors.Is(err, identitymodel.ErrWorkspaceIDRequired) {
			t.Fatalf("missing workspace operation %d error=%v", index, err)
		}
	}
}
