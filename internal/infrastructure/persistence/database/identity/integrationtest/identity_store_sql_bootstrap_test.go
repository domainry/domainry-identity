package identity_test

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityservice "github.com/domainry/domainry-identity/internal/domain/identity/service"

	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"

	"path/filepath"
	"testing"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestSQLIdentityUserReportingTreeReparentPersistsDescendantPaths(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-reporting-tree.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	service, err := identityservice.NewIdentityDomainService(identityStore, nil).ForWorkspace("workspace-primary")
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []identitymodel.IdentityUser{
		{ID: "manager-a", Name: "Manager A", Email: "manager-a@example.com", Status: identitymodel.IdentityStatusActive},
		{ID: "manager-b", Name: "Manager B", Email: "manager-b@example.com", Status: identitymodel.IdentityStatusActive},
		{ID: "employee", Name: "Employee", Email: "employee@example.com", ManagerUserID: "manager-a", Status: identitymodel.IdentityStatusActive},
		{ID: "report", Name: "Report", Email: "report@example.com", ManagerUserID: "employee", Status: identitymodel.IdentityStatusActive},
	} {
		if err := service.UpsertUser(t.Context(), user); err != nil {
			t.Fatalf("upsert %s: %v", user.ID, err)
		}
	}
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{
		ID: "employee", Name: "Employee", Email: "employee@example.com", ManagerUserID: "manager-b", Status: identitymodel.IdentityStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	users, err := identityStore.ListIdentityUsers(t.Context(), "workspace-primary")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]identitymodel.IdentityUser{}
	for _, user := range users {
		byID[user.ID] = user
	}
	if employee := byID["employee"]; employee.ManagerUserID != "manager-b" || employee.ReportingPath != "/manager-b/employee" {
		t.Fatalf("employee reporting facts not persisted: %#v", employee)
	}
	if report := byID["report"]; report.ManagerUserID != "employee" || report.ReportingPath != "/manager-b/employee/report" {
		t.Fatalf("descendant reporting path not rewritten: %#v", report)
	}
}

func TestApplyIdentityBootstrapAtomicallyRollsBackPartialGraph(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-bootstrap.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	err = identityStore.ApplyIdentityBootstrapAtomically(
		t.Context(),
		"workspace-primary",
		[]identitymodel.IdentityOrganizationUnit{{ID: "people", Name: "People", Path: "/people", Status: identitymodel.IdentityStatusActive}},
		[]identitymodel.IdentityUser{{ID: "employee", Name: "Employee", Email: "employee@example.com", OrgID: "people", WorkerNo: "E-1", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, Status: identitymodel.IdentityStatusActive}},
		[]identitymodel.IdentityUserRoleAssignment{{UserID: "employee", RoleID: ""}},
	)
	if err == nil {
		t.Fatal("expected invalid assignment to roll back Identity Bootstrap")
	}
	organizationUnits, listErr := identityStore.ListIdentityOrganizationUnits(t.Context(), "workspace-primary")
	if listErr != nil {
		t.Fatal(listErr)
	}
	users, listErr := identityStore.ListIdentityUsers(t.Context(), "workspace-primary")
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(organizationUnits) != 0 || len(users) != 0 {
		t.Fatalf("partial Identity graph survived rollback: organizationUnits=%#v users=%#v", organizationUnits, users)
	}
}

func TestApplyIdentityBootstrapAtomicallyPersistsUserRole(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-bootstrap-success.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	if err := identityStore.UpsertIdentityRole(t.Context(), "workspace-primary", identitymodel.IdentityRole{ID: "operator", Key: "operator", Label: "Operator", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	err = identityStore.ApplyIdentityBootstrapAtomically(
		t.Context(), "workspace-primary",
		[]identitymodel.IdentityOrganizationUnit{{ID: "people", Name: "People", Path: "/people", Status: identitymodel.IdentityStatusActive}},
		[]identitymodel.IdentityUser{{ID: "employee", Name: "Employee", Email: "employee@example.com", OrgID: "people", WorkerNo: "E-1", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, Status: identitymodel.IdentityStatusActive}},
		[]identitymodel.IdentityUserRoleAssignment{{UserID: "employee", RoleID: "operator"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	roleAssignments, err := identityStore.ListIdentityUserRoleAssignments(t.Context(), "workspace-primary", "employee")
	if err != nil {
		t.Fatal(err)
	}
	if len(roleAssignments) != 1 || roleAssignments[0].UserID != "employee" || roleAssignments[0].RoleID != "operator" {
		t.Fatalf("user role not persisted: %#v", roleAssignments)
	}
}
