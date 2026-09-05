package moduleassembly

import (
	"encoding/json"
	"strings"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"golang.org/x/crypto/bcrypt"
)

func TestAcceptanceFixturesMaterializeRoleOrgReportingAndCredentialGraph(t *testing.T) {
	roles := []identitymodel.IdentityRole{
		{ID: "role-director", Key: "sales_director"},
		{ID: "role-sales", Key: "sales_rep"},
	}
	request := identitysdk.WorkspaceIdentityProvisionRequest{
		AcceptanceOrganizations: []identitysdk.WorkspaceAcceptanceOrganization{
			{ID: "east", Code: "east", Name: "East"},
			{ID: "north", Code: "north", Name: "North"},
		},
		AcceptanceActors: []identitysdk.WorkspaceAcceptanceActor{
			{ID: "director", LoginID: "director@example.test", Name: "Director", RoleKey: "sales_director", InitialPassword: "DirectorPassword1!"},
			{ID: "sales-east", LoginID: "sales-east@example.test", Name: "East Sales", RoleKey: "sales_rep", OrganizationID: "east", ManagerUserID: "director", InitialPassword: "EastSalesPassword1!"},
			{ID: "sales-north", LoginID: "sales-north@example.test", Name: "North Sales", RoleKey: "sales_rep", OrganizationID: "north", ManagerUserID: "director", InitialPassword: "NorthSalesPassword1!"},
		},
	}
	organizations, users, assignments, credentials, err := acceptanceFixtures(request, roles)
	if err != nil {
		t.Fatal(err)
	}
	if len(organizations) != 2 || len(users) != 3 || len(assignments) != 3 || len(credentials) != 3 {
		t.Fatalf("fixture graph organizations=%d users=%d assignments=%d credentials=%d", len(organizations), len(users), len(assignments), len(credentials))
	}
	if users[0].ID != "director" || users[0].OrgID != "" || users[0].ReportingPath != "/director" ||
		users[1].OrgID != "east" || users[1].ManagerUserID != "director" || users[1].ReportingPath != "/director/sales-east" ||
		users[2].OrgID != "north" || users[2].ManagerUserID != "director" || users[2].ReportingPath != "/director/sales-north" {
		t.Fatalf("user graph=%+v", users)
	}
	if assignments[0].RoleID != "role-director" || assignments[1].RoleID != "role-sales" || assignments[2].RoleID != "role-sales" {
		t.Fatalf("role assignments=%+v", assignments)
	}
	for index, credential := range credentials {
		if credential.MustChangePassword || bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte(request.AcceptanceActors[index].InitialPassword)) != nil {
			t.Fatalf("credential %d does not match its one-time actor authority", index)
		}
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range request.AcceptanceActors {
		if strings.Contains(string(encoded), actor.InitialPassword) || strings.Contains(string(encoded), actor.LoginID) {
			t.Fatalf("embedded fixture leaked through public request JSON: %s", encoded)
		}
	}
}

func TestAcceptanceFixturesRejectMissingManager(t *testing.T) {
	_, _, _, _, err := acceptanceFixtures(identitysdk.WorkspaceIdentityProvisionRequest{
		AcceptanceOrganizations: []identitysdk.WorkspaceAcceptanceOrganization{{ID: "east", Code: "east", Name: "East"}},
		AcceptanceActors:        []identitysdk.WorkspaceAcceptanceActor{{ID: "sales", LoginID: "sales@example.test", Name: "Sales", RoleKey: "sales_rep", OrganizationID: "east", ManagerUserID: "missing", InitialPassword: "SalesPassword1!"}},
	}, []identitymodel.IdentityRole{{ID: "role-sales", Key: "sales_rep"}})
	if err == nil {
		t.Fatal("missing reporting-line manager was accepted")
	}
}

func TestAcceptanceFixturesDiagnoseUnknownProjectRoleWithoutCredentialDisclosure(t *testing.T) {
	const secret = "DirectorPassword1!"
	_, _, _, _, err := acceptanceFixtures(identitysdk.WorkspaceIdentityProvisionRequest{
		AcceptanceActors: []identitysdk.WorkspaceAcceptanceActor{{ID: "director", LoginID: "director@example.test", Name: "Director", RoleKey: "sales_director", InitialPassword: secret}},
	}, []identitymodel.IdentityRole{{ID: "role-admin", Key: "admin"}})
	identityErr, ok := err.(*identitysdk.Error)
	if !ok || identityErr.Code != "identity.workspace_acceptance_fixture_invalid" {
		t.Fatalf("error=%T %v", err, err)
	}
	if identityErr.Params["fixture_kind"] != "actor" || identityErr.Params["fixture_index"] != "0" || identityErr.Params["field"] != "role_key" || identityErr.Params["reason"] != "unknown" || identityErr.Params["role_key"] != "sales_director" {
		t.Fatalf("diagnostic params=%v", identityErr.Params)
	}
	encoded, marshalErr := json.Marshal(identityErr)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(identityErr.Error(), secret) || strings.Contains(string(encoded), secret) {
		t.Fatalf("fixture diagnostic disclosed credential: error=%v json=%s", identityErr, encoded)
	}
}

func TestAcceptanceFixturesDiagnosePasswordPolicyWithoutPasswordValue(t *testing.T) {
	const secret = "weak-secret"
	_, _, _, _, err := acceptanceFixtures(identitysdk.WorkspaceIdentityProvisionRequest{
		AcceptanceActors: []identitysdk.WorkspaceAcceptanceActor{{ID: "sales", LoginID: "sales@example.test", Name: "Sales", RoleKey: "sales_rep", InitialPassword: secret}},
	}, []identitymodel.IdentityRole{{ID: "role-sales", Key: "sales_rep"}})
	identityErr, ok := err.(*identitysdk.Error)
	if !ok || identityErr.Params["field"] != "initial_password" || identityErr.Params["reason"] != "policy_violation" {
		t.Fatalf("error=%T %v", err, err)
	}
	encoded, marshalErr := json.Marshal(identityErr)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("password value leaked through diagnostic: %s", encoded)
	}
}
