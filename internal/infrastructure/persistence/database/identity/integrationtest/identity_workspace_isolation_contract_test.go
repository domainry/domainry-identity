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
}

func assertIdentityRepositoryWorkspaceIsolation(t *testing.T, repository identityWorkspaceRepository) {
	t.Helper()
	ctx := t.Context()
	const workspaceA, workspaceB = "workspace-a", "workspace-b"
	organizationUnitA := identitymodel.IdentityOrganizationUnit{OrganizationUnitID: "organization-unit-a", Code: "A", Name: "Organization Unit A", NodeType: identitymodel.IdentityOrganizationUnitTeam, Path: "/organization-unit-a"}
	organizationUnitB := identitymodel.IdentityOrganizationUnit{OrganizationUnitID: "organization-unit-b", Code: "B", Name: "Organization Unit B", NodeType: identitymodel.IdentityOrganizationUnitStore, Path: "/organization-unit-b"}
	userA := identitymodel.IdentityUser{UserID: "user-a", Name: "User A", Email: "a@example.com", OrgID: organizationUnitA.OrganizationUnitID, WorkerNo: "A-001", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive}
	userB := identitymodel.IdentityUser{UserID: "user-b", Name: "User B", Email: "b@example.com", OrgID: organizationUnitB.OrganizationUnitID, WorkerNo: "B-001", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive}
	roleA := identitymodel.IdentityRole{RoleID: "role-a", Key: "role-a", Label: "Role A"}
	roleB := identitymodel.IdentityRole{RoleID: "role-b", Key: "role-b", Label: "Role B"}
	menuA := identitymodel.IdentityMenu{MenuID: "menu-a", SourceOwner: "application:test", Key: "menu-a", Label: "Menu A"}
	menuB := identitymodel.IdentityMenu{MenuID: "menu-b", SourceOwner: "application:test", Key: "menu-b", Label: "Menu B"}

	for _, seed := range []func() error{
		func() error { return repository.UpsertIdentityOrganizationUnit(ctx, workspaceA, organizationUnitA) },
		func() error { return repository.UpsertIdentityOrganizationUnit(ctx, workspaceB, organizationUnitB) },
		func() error { return repository.UpsertIdentityUser(ctx, workspaceA, userA) },
		func() error { return repository.UpsertIdentityUser(ctx, workspaceB, userB) },
		func() error { return repository.UpsertIdentityRole(ctx, workspaceA, roleA) },
		func() error { return repository.UpsertIdentityRole(ctx, workspaceB, roleB) },
		func() error {
			return repository.AssignIdentityUserRole(ctx, workspaceA, identitymodel.IdentityUserRoleAssignment{UserID: userA.UserID, RoleID: roleA.RoleID})
		},
		func() error {
			return repository.AssignIdentityUserRole(ctx, workspaceB, identitymodel.IdentityUserRoleAssignment{UserID: userB.UserID, RoleID: roleB.RoleID})
		},
		func() error { return repository.UpsertIdentityMenu(ctx, workspaceA, menuA) },
		func() error { return repository.UpsertIdentityMenu(ctx, workspaceB, menuB) },
		func() error {
			return repository.SetIdentityRoleMenus(ctx, workspaceA, roleA.RoleID, []string{menuA.MenuID})
		},
		func() error {
			return repository.SetIdentityRoleMenus(ctx, workspaceB, roleB.RoleID, []string{menuB.MenuID})
		},
	} {
		if err := seed(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repository.CreateIdentityRoleRequest(ctx, workspaceA, identitymodel.IdentityRoleRequest{RoleRequestID: "request-a", UserID: userA.UserID, RoleIDs: []string{roleA.RoleID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateIdentityRoleRequest(ctx, workspaceB, identitymodel.IdentityRoleRequest{RoleRequestID: "request-b", UserID: userB.UserID, RoleIDs: []string{roleB.RoleID}}); err != nil {
		t.Fatal(err)
	}

	organizationUnits, _ := repository.ListIdentityOrganizationUnits(ctx, workspaceA)
	users, _ := repository.ListIdentityUsers(ctx, workspaceA)
	roles, _ := repository.ListIdentityRoles(ctx, workspaceA)
	assignments, _ := repository.ListIdentityUserRoleAssignments(ctx, workspaceA, "")
	menus, _ := repository.ListIdentityMenus(ctx, workspaceA)
	roleMenus, _ := repository.ListIdentityRoleMenuAssignments(ctx, workspaceA, roleA.RoleID)
	requests, _ := repository.ListIdentityRoleRequests(ctx, workspaceA, "", "")
	if len(organizationUnits) != 1 || organizationUnits[0].OrganizationUnitID != organizationUnitA.OrganizationUnitID ||
		len(users) != 1 || users[0].UserID != userA.UserID ||
		len(roles) != 1 || roles[0].RoleID != roleA.RoleID ||
		len(assignments) != 1 || assignments[0].UserID != userA.UserID ||
		len(menus) != 2 || menus[0].MenuID != menuA.MenuID || menus[1].MenuID != menuB.MenuID ||
		len(roleMenus) != 1 || roleMenus[0].MenuID != menuA.MenuID ||
		len(requests) != 1 || requests[0].RoleRequestID != "request-a" {
		t.Fatalf("workspace A leaked or lost data: organizationUnits=%#v users=%#v roles=%#v assignments=%#v menus=%#v roleMenus=%#v requests=%#v", organizationUnits, users, roles, assignments, menus, roleMenus, requests)
	}
	if _, found, err := repository.GetIdentityUser(ctx, workspaceB, userA.UserID); err != nil || found {
		t.Fatalf("workspace B read workspace A user: found=%v err=%v", found, err)
	}
	_ = repository.SetIdentityUserStatus(ctx, workspaceB, userA.UserID, identitymodel.IdentityStatusDisabled)
	storedA, found, err := repository.GetIdentityUser(ctx, workspaceA, userA.UserID)
	if err != nil || !found || storedA.Status != identitymodel.IdentityStatusActive {
		t.Fatalf("cross-workspace status mutation changed A: user=%#v found=%v err=%v", storedA, found, err)
	}

	assertIdentityRepositoryRejectsMissingWorkspace(t, repository)
}

func assertIdentityRepositoryRejectsMissingWorkspace(t *testing.T, repository identityWorkspaceRepository) {
	t.Helper()
	ctx := t.Context()
	role := identitymodel.IdentityRole{RoleID: "missing-role"}
	operations := []func() error{
		func() error { _, err := repository.ListIdentityOrganizationUnits(ctx, ""); return err },
		func() error {
			return repository.UpsertIdentityOrganizationUnit(ctx, "", identitymodel.IdentityOrganizationUnit{OrganizationUnitID: "missing"})
		},
		func() error { _, err := repository.ListIdentityUsers(ctx, ""); return err },
		func() error { _, _, err := repository.GetIdentityUser(ctx, "", "user"); return err },
		func() error {
			return repository.UpsertIdentityUser(ctx, "", identitymodel.IdentityUser{UserID: "user"})
		},
		func() error { return repository.UpsertIdentityUsersAtomically(ctx, "", nil) },
		func() error { return repository.RemoveIdentityUser(ctx, "", "user") },
		func() error {
			return repository.SetIdentityUserStatus(ctx, "", "user", identitymodel.IdentityStatusDisabled)
		},
		func() error { return repository.UpsertIdentityRole(ctx, "", role) },
		func() error { return repository.RemoveIdentityRole(ctx, "", role.RoleID) },
		func() error {
			return repository.AssignIdentityUserRole(ctx, "", identitymodel.IdentityUserRoleAssignment{UserID: "user", RoleID: role.RoleID})
		},
		func() error { return repository.RemoveIdentityUserRole(ctx, "", "user", role.RoleID) },
		func() error { _, err := repository.ListIdentityUserRoleAssignments(ctx, "", "user"); return err },
		func() error {
			_, err := repository.CreateIdentityRoleRequest(ctx, "", identitymodel.IdentityRoleRequest{RoleRequestID: "request"})
			return err
		},
		func() error { _, err := repository.ListIdentityRoleRequests(ctx, "", "", ""); return err },
		func() error {
			return repository.UpdateIdentityRoleRequest(ctx, "", identitymodel.IdentityRoleRequest{RoleRequestID: "request"})
		},
	}
	for index, operation := range operations {
		if err := operation(); !errors.Is(err, identitymodel.ErrWorkspaceIDRequired) {
			t.Fatalf("missing workspace operation %d error=%v", index, err)
		}
	}
}
