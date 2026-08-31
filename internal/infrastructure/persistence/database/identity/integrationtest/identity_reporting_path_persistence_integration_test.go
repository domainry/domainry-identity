package identity_test

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitybusiness "github.com/domainry/domainry-identity/internal/domain/identity/service"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestPrincipalReportingFactsFollowActiveWorkforceAssignments(t *testing.T) {
	repository := identitypersistence.NewMemoryIdentityStore()
	service, _ := identitybusiness.NewIdentityDomainService(repository, nil).ForWorkspace("workspace-primary")
	for _, user := range []identitymodel.IdentityUser{
		{ID: "boss", Name: "Boss", Email: "boss@example.com"},
		{ID: "lead", Name: "Lead", Email: "lead@example.com"},
		{ID: "member", Name: "Member", Email: "member@example.com"},
	} {
		if err := service.UpsertUser(t.Context(), user); err != nil {
			t.Fatal(err)
		}
	}
	for _, profile := range []identitymodel.IdentityWorkforceProfile{
		{ID: "boss-workforce", OrganizationID: "organization", IdentityUserID: "boss", WorkerNo: "boss", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, PrimaryAssignmentID: "boss-primary"},
		{ID: "lead-workforce", OrganizationID: "organization", IdentityUserID: "lead", WorkerNo: "lead", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, PrimaryAssignmentID: "lead-primary"},
		{ID: "member-workforce", OrganizationID: "organization", IdentityUserID: "member", WorkerNo: "member", WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive, PrimaryAssignmentID: "member-primary"},
	} {
		if err := repository.UpsertIdentityWorkforceProfile(t.Context(), "workspace-primary", profile); err != nil {
			t.Fatal(err)
		}
	}
	for _, assignment := range []identitymodel.IdentityWorkforceAssignment{
		{ID: "boss-primary", WorkforceProfileID: "boss-workforce", OrganizationUnitID: "unit", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
		{ID: "lead-primary", WorkforceProfileID: "lead-workforce", OrganizationUnitID: "unit", ManagerWorkforceProfileID: "boss-workforce", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
		{ID: "member-primary", WorkforceProfileID: "member-workforce", OrganizationUnitID: "unit", ManagerWorkforceProfileID: "lead-workforce", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
	} {
		if err := repository.UpsertIdentityWorkforceAssignment(t.Context(), "workspace-primary", assignment); err != nil {
			t.Fatal(err)
		}
	}
	principal, err := service.BuildPrincipal(t.Context(), "member")
	if err != nil || principal.ReportingPath != "/boss/lead/member" {
		t.Fatalf("principal=%#v err=%v", principal, err)
	}
	if err := repository.UpsertIdentityWorkforceAssignment(t.Context(), "workspace-primary", identitymodel.IdentityWorkforceAssignment{
		ID: "lead-primary", WorkforceProfileID: "lead-workforce", OrganizationUnitID: "unit",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	principal, err = service.BuildPrincipal(t.Context(), "member")
	if err != nil || principal.ReportingPath != "/lead/member" {
		t.Fatalf("moved principal=%#v err=%v", principal, err)
	}
}
