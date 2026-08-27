package service

import (
	"context"
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type nativeIdentityDirectoryRepository struct {
	*identityRolesRepositoryStub
	userPage      identitymodel.IdentityUserPage
	workforcePage identitymodel.IdentityWorkforceProfilePage
}

func (r *nativeIdentityDirectoryRepository) SearchIdentityUsers(context.Context, string, identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
	return r.userPage, r.err
}

func (r *nativeIdentityDirectoryRepository) SearchIdentityWorkforceProfiles(context.Context, string, identitymodel.IdentityListQuery) (identitymodel.IdentityWorkforceProfilePage, error) {
	return r.workforcePage, r.err
}

func TestIdentityDirectoryNativeSearchCapabilities(t *testing.T) {
	repository := &nativeIdentityDirectoryRepository{
		identityRolesRepositoryStub: &identityRolesRepositoryStub{workforceProfiles: []identitymodel.IdentityWorkforceProfile{{ID: "owned", IdentityUserID: "user"}}},
		userPage:                    identitymodel.IdentityUserPage{Total: 7},
		workforcePage:               identitymodel.IdentityWorkforceProfilePage{Total: 9},
	}
	service, err := NewIdentityDomainService(repository, nil).ForWorkspace("default")
	if err != nil {
		t.Fatal(err)
	}
	if page, err := service.SearchUsers(t.Context(), identitymodel.IdentityListQuery{}); err != nil || page.Total != 7 {
		t.Fatalf("users=%+v err=%v", page, err)
	}
	if page, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{}); err != nil || page.Total != 9 {
		t.Fatalf("workforce=%+v err=%v", page, err)
	}
	if page, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{Scope: "all_records"}); err != nil || page.Total != 9 {
		t.Fatalf("all workforce=%+v err=%v", page, err)
	}
	if page, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{Scope: "owned_records", PrincipalUserID: "other"}); err != nil || page.Total != 0 {
		t.Fatalf("scoped workforce=%+v err=%v", page, err)
	}
	if page, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{Scope: "owned_records", PrincipalUserID: "user"}); err != nil || page.Total != 1 {
		t.Fatalf("owned workforce=%+v err=%v", page, err)
	}
}

func TestIdentityWorkforceScopedProfileIDs(t *testing.T) {
	repository := &identityRolesRepositoryStub{
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{
			{ID: "self", IdentityUserID: "self-user", PrimaryAssignmentID: "self-assignment"},
			{ID: "report", IdentityUserID: "report-user"},
			{ID: "child", IdentityUserID: "child-user"},
			{ID: "other", IdentityUserID: "other-user"},
			{ID: "unassigned", IdentityUserID: "unassigned-user"},
		},
		workforceAssignments: []identitymodel.IdentityWorkforceAssignment{
			{ID: "wrong-profile", WorkforceProfileID: "other", OrganizationUnitID: "other"},
			{ID: "self-assignment", WorkforceProfileID: "self", OrganizationUnitID: "sales", AssignmentType: identitymodel.IdentityWorkforceAssignmentSecondary, Status: identitymodel.IdentityStatusDisabled},
			{ID: "report-primary", WorkforceProfileID: "report", OrganizationUnitID: "sales", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
			{ID: "child-primary", WorkforceProfileID: "child", OrganizationUnitID: "sales-east", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
			{ID: "inactive", WorkforceProfileID: "other", OrganizationUnitID: "other", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusDisabled},
			{ID: "other-active", WorkforceProfileID: "other", OrganizationUnitID: "other", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
		},
		departments: []identitymodel.IdentityDepartment{
			{ID: "sales", Path: "/company/sales/"}, {ID: "sales-east", Path: "/company/sales/east"}, {ID: "other", Path: "/company/other"},
		},
	}
	service := directorySearchService(t, repository)
	profiles := repository.workforceProfiles
	for _, test := range []struct {
		query identitymodel.IdentityListQuery
		want  map[string]bool
	}{
		{query: identitymodel.IdentityListQuery{}, want: nil},
		{query: identitymodel.IdentityListQuery{Scope: "all_records"}, want: nil},
		{query: identitymodel.IdentityListQuery{Scope: "owned_records", PrincipalUserID: "self-user"}, want: map[string]bool{"self": true}},
		{query: identitymodel.IdentityListQuery{Scope: "none", PrincipalUserID: "self-user"}, want: map[string]bool{}},
		{query: identitymodel.IdentityListQuery{Scope: "custom"}, want: map[string]bool{}},
		{query: identitymodel.IdentityListQuery{Scope: "subordinates", PrincipalUserID: "self-user", PrincipalReportingUserIDs: []string{" report-user "}}, want: map[string]bool{"self": true, "report": true}},
		{query: identitymodel.IdentityListQuery{Scope: "team", PrincipalReportingUserIDs: []string{"report-user"}}, want: map[string]bool{"report": true}},
		{query: identitymodel.IdentityListQuery{Scope: "team", PrincipalUserID: "self-user"}, want: map[string]bool{"self": true}},
		{query: identitymodel.IdentityListQuery{Scope: "department", PrincipalUserID: "self-user"}, want: map[string]bool{"self": true}},
		{query: identitymodel.IdentityListQuery{Scope: "department_and_children", PrincipalUserID: "self-user"}, want: map[string]bool{"self": true}},
		{query: identitymodel.IdentityListQuery{Scope: "unsupported"}, want: map[string]bool{}},
		{query: identitymodel.IdentityListQuery{Scope: "department"}, want: map[string]bool{}},
		{query: identitymodel.IdentityListQuery{Scope: "department", PrincipalDepartmentPath: "/company/sales/"}, want: map[string]bool{"self": true, "report": true}},
		{query: identitymodel.IdentityListQuery{Scope: "department_and_children", PrincipalDepartmentPath: "/company/sales"}, want: map[string]bool{"self": true, "report": true, "child": true}},
	} {
		got, err := service.identityWorkforceScopedProfileIDs(t.Context(), test.query, profiles)
		if err != nil || !sameStringBoolMap(got, test.want) {
			t.Fatalf("query=%+v got=%v want=%v err=%v", test.query, got, test.want, err)
		}
	}
	repository.workforceAssignmentsErr = errors.New("assignments")
	if _, err := service.identityWorkforceScopedProfileIDs(t.Context(), identitymodel.IdentityListQuery{Scope: "department"}, profiles); !errors.Is(err, repository.workforceAssignmentsErr) {
		t.Fatalf("assignment err=%v", err)
	}
	if _, err := service.SearchWorkforceProfiles(t.Context(), identitymodel.IdentityListQuery{Scope: "department"}); !errors.Is(err, repository.workforceAssignmentsErr) {
		t.Fatalf("search scope err=%v", err)
	}
	repository.workforceAssignmentsErr = nil
	repository.departmentsErr = errors.New("departments")
	if _, err := service.identityWorkforceScopedProfileIDs(t.Context(), identitymodel.IdentityListQuery{Scope: "department"}, profiles); !errors.Is(err, repository.departmentsErr) {
		t.Fatalf("department err=%v", err)
	}
	withoutWorkforce, err := NewIdentityDomainService(&identityDepartmentUserRepository{}, nil).ForWorkspace("default")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutWorkforce.identityWorkforceScopedProfileIDs(t.Context(), identitymodel.IdentityListQuery{Scope: "department"}, profiles); err == nil {
		t.Fatal("missing workforce repository accepted")
	}
}

func TestWorkforcePrimaryAssignmentForSearchRemainingBranches(t *testing.T) {
	profile := identitymodel.IdentityWorkforceProfile{ID: "profile", PrimaryAssignmentID: "preferred"}
	assignments := []identitymodel.IdentityWorkforceAssignment{
		{ID: "other-profile", WorkforceProfileID: "other", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
		{ID: "not-preferred", WorkforceProfileID: "profile", AssignmentType: identitymodel.IdentityWorkforceAssignmentSecondary, Status: identitymodel.IdentityStatusActive},
		{ID: "fallback-disabled", WorkforceProfileID: "profile", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusDisabled},
		{ID: "fallback", WorkforceProfileID: "profile", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
	}
	if assignment, found := workforcePrimaryAssignmentForSearch(profile, assignments); !found || assignment.ID != "fallback" {
		t.Fatalf("assignment=%+v found=%v", assignment, found)
	}
	assignments = append(assignments, identitymodel.IdentityWorkforceAssignment{ID: "preferred", WorkforceProfileID: "profile"})
	if assignment, found := workforcePrimaryAssignmentForSearch(profile, assignments); !found || assignment.ID != "preferred" {
		t.Fatalf("preferred=%+v found=%v", assignment, found)
	}
	if _, found := workforcePrimaryAssignmentForSearch(profile, nil); found {
		t.Fatal("missing assignment accepted")
	}
}

func sameStringBoolMap(left, right map[string]bool) bool {
	if len(left) != len(right) || (left == nil) != (right == nil) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
