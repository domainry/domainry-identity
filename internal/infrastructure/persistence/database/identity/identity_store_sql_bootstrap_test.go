package identity_test

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"

	"path/filepath"
	"testing"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

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
		identitymodel.InstallationWorkspaceID,
		[]identitymodel.IdentityDepartment{{ID: "people", Name: "People", Path: "/people", Status: identitymodel.IdentityStatusActive}},
		[]identitymodel.IdentityUser{{ID: "employee", Name: "Employee", Email: "employee@example.com", Status: identitymodel.IdentityStatusActive}},
		[]identitymodel.IdentityWorkforceProfile{{ID: "employee-workforce", OrganizationID: "organization", IdentityUserID: "employee", WorkerNo: "E-1", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive}},
		[]identitymodel.IdentityWorkforceAssignment{{ID: "employee-primary", WorkforceProfileID: "employee-workforce", OrganizationUnitID: "people", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive}},
		[]identitymodel.IdentityUserRoleAssignment{{UserID: "employee", RoleID: "", WorkforceProfileID: "employee-workforce"}},
	)
	if err == nil {
		t.Fatal("expected invalid assignment to roll back Identity Bootstrap")
	}
	departments, listErr := identityStore.ListIdentityDepartments(t.Context(), identitymodel.InstallationWorkspaceID)
	if listErr != nil {
		t.Fatal(listErr)
	}
	users, listErr := identityStore.ListIdentityUsers(t.Context(), identitymodel.InstallationWorkspaceID)
	if listErr != nil {
		t.Fatal(listErr)
	}
	profiles, listErr := identityStore.ListIdentityWorkforceProfiles(t.Context(), identitymodel.InstallationWorkspaceID)
	if listErr != nil {
		t.Fatal(listErr)
	}
	assignments, listErr := identityStore.ListIdentityWorkforceAssignments(t.Context(), identitymodel.InstallationWorkspaceID, "")
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(departments) != 0 || len(users) != 0 || len(profiles) != 0 || len(assignments) != 0 {
		t.Fatalf("partial Identity graph survived rollback: departments=%#v users=%#v profiles=%#v assignments=%#v", departments, users, profiles, assignments)
	}
}

func TestApplyIdentityBootstrapAtomicallyPersistsWorkforceBoundRole(t *testing.T) {
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
	if err := identityStore.UpsertIdentityRole(t.Context(), identitymodel.InstallationWorkspaceID, identitymodel.IdentityRole{ID: "operator", Key: "operator", Label: "Operator", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	err = identityStore.ApplyIdentityBootstrapAtomically(
		t.Context(), identitymodel.InstallationWorkspaceID,
		[]identitymodel.IdentityDepartment{{ID: "people", Name: "People", Path: "/people", Status: identitymodel.IdentityStatusActive}},
		[]identitymodel.IdentityUser{{ID: "employee", Name: "Employee", Email: "employee@example.com", Status: identitymodel.IdentityStatusActive}},
		[]identitymodel.IdentityWorkforceProfile{{ID: "employee-workforce", OrganizationID: "organization", IdentityUserID: "employee", WorkerNo: "E-1", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive}},
		[]identitymodel.IdentityWorkforceAssignment{{ID: "employee-primary", WorkforceProfileID: "employee-workforce", OrganizationUnitID: "people", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive}},
		[]identitymodel.IdentityUserRoleAssignment{{UserID: "employee", RoleID: "operator", WorkforceProfileID: "employee-workforce"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	roleAssignments, err := identityStore.ListIdentityUserRoleAssignments(t.Context(), identitymodel.InstallationWorkspaceID, "employee")
	if err != nil {
		t.Fatal(err)
	}
	if len(roleAssignments) != 1 || roleAssignments[0].WorkforceProfileID != "employee-workforce" {
		t.Fatalf("workforce-bound role not persisted: %#v", roleAssignments)
	}
}
