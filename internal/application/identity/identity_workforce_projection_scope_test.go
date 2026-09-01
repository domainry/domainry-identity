package identity

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityWorkforceReadScopeAllowsOnlyAuthorizedProfiles(t *testing.T) {
	department := identitymodel.IdentityDepartment{ID: "sales", Path: "/company/sales"}
	child := identitymodel.IdentityDepartment{ID: "sales-east", Path: "/company/sales/east"}
	departments := map[string]identitymodel.IdentityDepartment{department.ID: department, child.ID: child}
	profile := identitymodel.IdentityWorkforceProfile{ID: "worker", IdentityUserID: "employee", PrimaryAssignmentID: "assignment"}
	assignments := []identitymodel.IdentityWorkforceAssignment{{
		ID: "assignment", WorkforceProfileID: profile.ID, OrganizationUnitID: child.ID,
		AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
	}}

	for _, test := range []struct {
		name      string
		principal identitymodel.Principal
		allowed   bool
	}{
		{name: "empty scope denied", principal: identitymodel.Principal{Known: true, UserID: "manager"}},
		{name: "functional Permission does not grant data scope", principal: identitymodel.Principal{Known: true, UserID: "manager", Role: identitymodel.RoleSchema{Permissions: []string{"identity.roles.list"}}}},
		{name: "explicit all records scope allowed", principal: identitymodel.Principal{Known: true, UserID: "manager", Role: identitymodel.RoleSchema{RecordScope: "all_records"}}, allowed: true},
		{name: "unrelated owned denied", principal: identitymodel.Principal{Known: true, UserID: "manager", Role: identitymodel.RoleSchema{RecordScope: "owned_records"}}},
		{name: "self owned allowed", principal: identitymodel.Principal{Known: true, UserID: "employee", Role: identitymodel.RoleSchema{RecordScope: "owned_records"}}, allowed: true},
		{name: "subordinate allowed", principal: identitymodel.Principal{Known: true, UserID: "manager", ReportingUserIDs: []string{"employee"}, Role: identitymodel.RoleSchema{RecordScope: "subordinates"}}, allowed: true},
		{name: "other subordinate denied", principal: identitymodel.Principal{Known: true, UserID: "manager", ReportingUserIDs: []string{"other"}, Role: identitymodel.RoleSchema{RecordScope: "subordinates"}}},
		{name: "department exact denied for child", principal: identitymodel.Principal{Known: true, UserID: "manager", DepartmentPath: department.Path, Role: identitymodel.RoleSchema{RecordScope: "department"}}},
		{name: "department children allowed", principal: identitymodel.Principal{Known: true, UserID: "manager", DepartmentPath: department.Path, Role: identitymodel.RoleSchema{RecordScope: "department_and_children"}}, allowed: true},
		{name: "data permission overrides empty legacy scope", principal: identitymodel.Principal{Known: true, UserID: "manager", DepartmentPath: department.Path, Role: identitymodel.RoleSchema{DataPermissions: []identitymodel.DataPermission{{ObjectKey: "identity_workforce_profile", Scope: "department_and_children", Read: true}}}}, allowed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := identityWorkforceReadScopeAllows(test.principal, profile, assignments, departments); got != test.allowed {
				t.Fatalf("allowed=%v want=%v", got, test.allowed)
			}
		})
	}
}

func TestFilterWorkforceApplicationProjectionUsesServerQueryControls(t *testing.T) {
	items := []identitymodel.IdentityWorkforceProjectionItem{
		{Profile: identitymodel.IdentityWorkforceProfile{ID: "a", WorkerNo: "E-001", WorkStatus: identitymodel.IdentityWorkActive}, DisplayName: "Alice", Department: &identitymodel.IdentityDepartment{ID: "sales", Name: "Sales"}, Position: &identitymodel.IdentityWorkforcePosition{ID: "p1", Code: "MGR", Name: "Manager"}},
		{Profile: identitymodel.IdentityWorkforceProfile{ID: "b", WorkerNo: "E-002", WorkStatus: identitymodel.IdentityWorkTerminated}, DisplayName: "Bob", Department: &identitymodel.IdentityDepartment{ID: "ops", Name: "Operations"}},
	}
	filtered := filterWorkforceApplicationProjection(items, identitymodel.IdentityWorkforceProjectionQuery{Search: "manager", DepartmentID: "sales", WorkStatus: identitymodel.IdentityWorkActive})
	if len(filtered) != 1 || filtered[0].Profile.ID != "a" {
		t.Fatalf("filtered=%+v", filtered)
	}
}
