package service

import (
	"errors"
	"reflect"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityWorkforcePeriodActiveFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		from, to   string
		wantActive bool
	}{
		{name: "unbounded", wantActive: true},
		{name: "date range", from: "2026-07-25", to: "2026-07-25", wantActive: true},
		{name: "timestamp range", from: "2026-07-25T11:00:00Z", to: "2026-07-25T13:00:00Z", wantActive: true},
		{name: "future", from: "2026-07-26"},
		{name: "ended", to: "2026-07-24"},
		{name: "invalid start", from: "not-a-date"},
		{name: "invalid end", to: "not-a-date"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := identityWorkforcePeriodActive(test.from, test.to, now); got != test.wantActive {
				t.Fatalf("active=%v want=%v", got, test.wantActive)
			}
		})
	}
	if _, ok := identityWorkforceTime("", false); ok {
		t.Fatal("blank workforce time was accepted")
	}
	if _, ok := identityWorkforceTime("not-a-date", false); ok {
		t.Fatal("invalid workforce time was accepted")
	}
}

func TestIdentityActivePrimaryAssignmentsSelectsDeclaredPrimary(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	profiles := map[string]identitymodel.IdentityWorkforceProfile{
		"profile": {ID: "profile", PrimaryAssignmentID: "preferred"},
	}
	assignments := []identitymodel.IdentityWorkforceAssignment{
		{ID: "missing-profile", WorkforceProfileID: "missing", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
		{ID: "disabled", WorkforceProfileID: "profile", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusDisabled},
		{ID: "secondary", WorkforceProfileID: "profile", AssignmentType: identitymodel.IdentityWorkforceAssignmentSecondary, Status: identitymodel.IdentityStatusActive},
		{ID: "future", WorkforceProfileID: "profile", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, EffectiveFrom: "2026-07-26", Status: identitymodel.IdentityStatusActive},
		{ID: "alphabetical", WorkforceProfileID: "profile", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
		{ID: "preferred", WorkforceProfileID: "profile", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
	}
	got := identityActivePrimaryAssignments(assignments, profiles, now)
	if len(got) != 1 || got["profile"].ID != "preferred" {
		t.Fatalf("active primary assignments=%#v", got)
	}
	profiles["profile"] = identitymodel.IdentityWorkforceProfile{ID: "profile", PrimaryAssignmentID: "absent"}
	got = identityActivePrimaryAssignments(assignments, profiles, now)
	if got["profile"].ID != "alphabetical" {
		t.Fatalf("fallback primary assignment=%#v", got)
	}
}

func TestIdentityWorkforceDirectoryUsesOnlyActiveWorkforceGraph(t *testing.T) {
	repository := &identityPrincipalRoleRepository{
		identityRolesRepositoryStub: &identityRolesRepositoryStub{},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{
			{ID: "manager", IdentityUserID: "manager-user", WorkStatus: identitymodel.IdentityWorkActive, PrimaryAssignmentID: "manager-primary"},
			{ID: "employee", IdentityUserID: "employee-user", WorkStatus: identitymodel.IdentityWorkActive, PrimaryAssignmentID: "employee-primary"},
			{ID: "member-only", IdentityUserID: "member-user", WorkStatus: identitymodel.IdentityWorkTerminated},
			{ID: "future", IdentityUserID: "future-user", WorkStatus: identitymodel.IdentityWorkActive, StartDate: "2999-01-01"},
			{ID: "unassigned", IdentityUserID: "unassigned-user", WorkStatus: identitymodel.IdentityWorkActive},
		},
		workforceAssignments: []identitymodel.IdentityWorkforceAssignment{
			{ID: "manager-primary", WorkforceProfileID: "manager", OrganizationUnitID: "sales", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
			{ID: "employee-primary", WorkforceProfileID: "employee", OrganizationUnitID: "sales", ManagerWorkforceProfileID: "manager", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
		},
		workforceEntries: []identitymodel.IdentityWorkforceDirectoryEntry{{OrganizationUnitID: "sales", OrganizationPath: "/company/sales"}},
	}
	service := principalRoleService(t, repository)
	entries, err := service.ListDirectoryWorkforce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []identitymodel.IdentityWorkforceDirectoryEntry{
		{WorkforceProfileID: "employee", IdentityUserID: "employee-user", OrganizationUnitID: "sales", OrganizationPath: "/company/sales", ManagerIdentityUserID: "manager-user", ReportingPath: "/manager-user/employee-user"},
		{WorkforceProfileID: "manager", IdentityUserID: "manager-user", OrganizationUnitID: "sales", OrganizationPath: "/company/sales", ReportingPath: "/manager-user"},
		{WorkforceProfileID: "unassigned", IdentityUserID: "unassigned-user", ReportingPath: "/unassigned-user"},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("directory=%#v want=%#v", entries, want)
	}
	facts, activeProfiles, err := service.resolveWorkforceFacts(t.Context(), "manager-user", time.Now())
	if err != nil || facts.DepartmentID != "sales" || !reflect.DeepEqual(facts.ReportingUserIDs, []string{"employee-user"}) || !activeProfiles["manager"] {
		t.Fatalf("facts=%#v active=%#v err=%v", facts, activeProfiles, err)
	}
	memberFacts, _, err := service.resolveWorkforceFacts(t.Context(), "member-user", time.Now())
	if err != nil || memberFacts.ProfileID != "" {
		t.Fatalf("member-only facts=%#v err=%v", memberFacts, err)
	}
	repository.workforceProfiles = append(repository.workforceProfiles,
		identitymodel.IdentityWorkforceProfile{ID: "z-profile", IdentityUserID: "duplicate-user", WorkStatus: identitymodel.IdentityWorkActive},
		identitymodel.IdentityWorkforceProfile{ID: "a-profile", IdentityUserID: "duplicate-user", WorkStatus: identitymodel.IdentityWorkActive},
	)
	duplicateFacts, _, err := service.resolveWorkforceFacts(t.Context(), "duplicate-user", time.Now())
	if err != nil || duplicateFacts.ProfileID != "a-profile" {
		t.Fatalf("duplicate facts=%#v err=%v", duplicateFacts, err)
	}
}

func TestIdentityWorkforceReportingGraphTerminatesOnCyclesAndMissingProfiles(t *testing.T) {
	profiles := map[string]identitymodel.IdentityWorkforceProfile{
		"a": {ID: "a", IdentityUserID: "user-a"},
		"b": {ID: "b", IdentityUserID: "user-b"},
		"c": {ID: "c", IdentityUserID: "user-c"},
		"d": {ID: "d", IdentityUserID: "user-d"},
		"e": {ID: "e", IdentityUserID: "user-e"},
	}
	assignments := map[string]identitymodel.IdentityWorkforceAssignment{
		"a": {WorkforceProfileID: "a", ManagerWorkforceProfileID: "b"},
		"b": {WorkforceProfileID: "b", ManagerWorkforceProfileID: "a"},
		"c": {WorkforceProfileID: "c", ManagerWorkforceProfileID: "missing"},
		"d": {WorkforceProfileID: "d", ManagerWorkforceProfileID: "e"},
		"e": {WorkforceProfileID: "e", ManagerWorkforceProfileID: "d"},
	}
	if path := identityWorkforceReportingPath("a", profiles, assignments); path != "/user-b/user-a" {
		t.Fatalf("cyclic reporting path=%q", path)
	}
	if path := identityWorkforceReportingPath("missing", profiles, assignments); path != "" {
		t.Fatalf("missing reporting path=%q", path)
	}
	if users := identityWorkforceReportingUsers("a", profiles, assignments); !reflect.DeepEqual(users, []string{"user-b"}) {
		t.Fatalf("cyclic reporting users=%#v", users)
	}
}

func TestIdentityWorkforceSnapshotPropagatesRepositoryFailures(t *testing.T) {
	failure := errors.New("workforce snapshot failed")
	for _, configure := range []func(*identityPrincipalRoleRepository){
		func(repository *identityPrincipalRoleRepository) { repository.workforceProfilesErr = failure },
		func(repository *identityPrincipalRoleRepository) { repository.workforceAssignmentsErr = failure },
		func(repository *identityPrincipalRoleRepository) { repository.departmentsErr = failure },
	} {
		repository := &identityPrincipalRoleRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{}}
		configure(repository)
		if _, err := principalRoleService(t, repository).ListDirectoryWorkforce(t.Context()); !errors.Is(err, failure) {
			t.Fatalf("snapshot error=%v", err)
		}
	}
	service := principalRoleService(t, &identityPrincipalRoleRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{}})
	service.repo = &identityRolesRepositoryStub{}
	if entries, err := service.ListDirectoryWorkforce(t.Context()); err != nil || len(entries) != 0 {
		t.Fatalf("repository without Workforce entries=%#v err=%v", entries, err)
	}
}

func TestWorkforceBoundRoleEndsWithoutEndingUnboundMemberRole(t *testing.T) {
	repository := &identityPrincipalRoleRepository{
		identityRolesRepositoryStub: &identityRolesRepositoryStub{
			users: []identitymodel.IdentityUser{{ID: "dual-user", Status: identitymodel.IdentityStatusActive}},
			roles: []identitymodel.IdentityRole{
				{ID: "employee", Key: "employee", Status: identitymodel.IdentityStatusActive},
				{ID: "member", Key: "member", Status: identitymodel.IdentityStatusActive},
			},
			assignments: []identitymodel.IdentityUserRoleAssignment{
				{UserID: "dual-user", RoleID: "employee", WorkforceProfileID: "dual-workforce"},
				{UserID: "dual-user", RoleID: "member"},
			},
		},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{
			{ID: "dual-workforce", IdentityUserID: "dual-user", WorkStatus: identitymodel.IdentityWorkActive},
		},
	}
	service := principalRoleService(t, repository)
	activateIdentityTestPermissions(service, "backoffice.read", "member.self.read")
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "employee", Permissions: []string{"backoffice.read"}},
		{Key: "member", Permissions: []string{"member.self.read"}},
	})
	principal, err := service.BuildPrincipal(t.Context(), "dual-user")
	if err != nil || !reflect.DeepEqual(principal.Role.Permissions, []string{"backoffice.read", "member.self.read"}) {
		t.Fatalf("active dual principal=%#v err=%v", principal, err)
	}
	repository.workforceProfiles[0].WorkStatus = identitymodel.IdentityWorkTerminated
	principal, err = service.BuildPrincipal(t.Context(), "dual-user")
	if err != nil || !reflect.DeepEqual(principal.Role.Permissions, []string{"member.self.read"}) {
		t.Fatalf("terminated Workforce principal=%#v err=%v", principal, err)
	}
}
