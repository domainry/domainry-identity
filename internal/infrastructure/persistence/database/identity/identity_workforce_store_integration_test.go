package identity_test

import (
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityWorkforceStoresPreserveWorkspaceAndAssignmentHistory(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		assertIdentityWorkforceStore(t, identitypersistence.NewMemoryIdentityStore())
	})
	t.Run("sqlite", func(t *testing.T) {
		store, err := database.OpenContext(t.Context(), config.Config{
			DatabaseDriver: "sqlite",
			DBPath:         filepath.Join(t.TempDir(), "identity-workforce.db"),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		if err := store.EnsureIdentitySchema(t.Context()); err != nil {
			t.Fatal(err)
		}
		repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceDialect())
		if err != nil {
			t.Fatal(err)
		}
		assertIdentityWorkforceStore(t, repository)
	})
}

func assertIdentityWorkforceStore(t *testing.T, repository identityrepository.IdentityWorkforceRepository) {
	t.Helper()
	profile := identitymodel.IdentityWorkforceProfile{
		ID: "workforce-1", OrganizationID: "organization-1", IdentityUserID: "user-1",
		WorkerNo: "E-001", WorkerType: identitymodel.IdentityWorkerEmployee,
		WorkStatus: identitymodel.IdentityWorkActive, StartDate: "2026-01-01",
	}
	if err := repository.UpsertIdentityWorkforceProfile(t.Context(), "workspace-a", profile); err != nil {
		t.Fatal(err)
	}
	profile.WorkerNo = "E-OTHER"
	if err := repository.UpsertIdentityWorkforceProfile(t.Context(), "workspace-b", profile); err != nil {
		t.Fatal(err)
	}
	duplicate := profile
	duplicate.ID = "workforce-duplicate"
	duplicate.WorkerNo = "E-001"
	if err := repository.UpsertIdentityWorkforceProfile(t.Context(), "workspace-a", duplicate); err == nil {
		t.Fatal("duplicate workforce identity binding was accepted")
	}
	assignment := identitymodel.IdentityWorkforceAssignment{
		ID: "assignment-primary", WorkforceProfileID: "workforce-1", OrganizationUnitID: "department-sales",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, EffectiveFrom: "2026-01-01",
		Status: identitymodel.IdentityStatusActive,
	}
	if err := repository.UpsertIdentityWorkforceAssignment(t.Context(), "workspace-a", assignment); err != nil {
		t.Fatal(err)
	}
	historical := identitymodel.IdentityWorkforceAssignment{
		ID: "assignment-history", WorkforceProfileID: "workforce-1", OrganizationUnitID: "department-support",
		ManagerWorkforceProfileID: "workforce-manager", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary,
		EffectiveFrom: "2025-01-01", EffectiveTo: "2025-12-31", Status: identitymodel.IdentityStatusDisabled,
	}
	if err := repository.UpsertIdentityWorkforceAssignment(t.Context(), "workspace-a", historical); err != nil {
		t.Fatal(err)
	}
	assignment.ID = "assignment-temporary"
	assignment.OrganizationUnitID = "store-east"
	assignment.AssignmentType = identitymodel.IdentityWorkforceAssignmentTemporary
	assignment.EffectiveFrom, assignment.EffectiveTo = "2026-07-01", "2026-07-07"
	if err := repository.UpsertIdentityWorkforceAssignment(t.Context(), "workspace-a", assignment); err != nil {
		t.Fatal(err)
	}
	profiles, err := repository.ListIdentityWorkforceProfiles(t.Context(), "workspace-a")
	if err != nil || len(profiles) != 1 || profiles[0].WorkerNo != "E-001" || profiles[0].Version != 1 {
		t.Fatalf("workspace-a profiles=%#v err=%v", profiles, err)
	}
	otherProfiles, err := repository.ListIdentityWorkforceProfiles(t.Context(), "workspace-b")
	if err != nil || len(otherProfiles) != 1 || otherProfiles[0].WorkerNo != "E-OTHER" {
		t.Fatalf("workspace-b profiles=%#v err=%v", otherProfiles, err)
	}
	assignments, err := repository.ListIdentityWorkforceAssignments(t.Context(), "workspace-a", "workforce-1")
	if err != nil || len(assignments) != 3 ||
		assignments[0].ID != "assignment-history" ||
		assignments[0].ManagerWorkforceProfileID != "workforce-manager" ||
		assignments[0].EffectiveTo != "2025-12-31" ||
		assignments[1].ID != "assignment-primary" ||
		assignments[2].ID != "assignment-temporary" {
		t.Fatalf("assignments=%#v err=%v", assignments, err)
	}
	if loaded, ok, err := repository.GetIdentityWorkforceProfile(t.Context(), "workspace-a", "workforce-1"); err != nil || !ok || loaded.IdentityUserID != "user-1" {
		t.Fatalf("profile=%#v ok=%v err=%v", loaded, ok, err)
	}
	if loaded, ok, err := repository.GetIdentityWorkforceAssignment(t.Context(), "workspace-a", "assignment-primary"); err != nil || !ok || loaded.OrganizationUnitID != "department-sales" {
		t.Fatalf("assignment=%#v ok=%v err=%v", loaded, ok, err)
	}
	if _, ok, err := repository.GetIdentityWorkforceProfile(t.Context(), "workspace-b", "missing"); err != nil || ok {
		t.Fatalf("missing profile ok=%v err=%v", ok, err)
	}
	if _, ok, err := repository.GetIdentityWorkforceAssignment(t.Context(), "workspace-b", "assignment-primary"); err != nil || ok {
		t.Fatalf("cross-workspace assignment ok=%v err=%v", ok, err)
	}
}
