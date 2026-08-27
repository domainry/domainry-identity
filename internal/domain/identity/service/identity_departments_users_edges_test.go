package service

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

var errIdentityDepartmentUserEdge = errors.New("identity department/user edge")

type identityDepartmentUserRepository struct {
	identityrepository.IdentityRepository
	departments       []identitymodel.IdentityDepartment
	users             []identitymodel.IdentityUser
	departmentLists   [][]identitymodel.IdentityDepartment
	userLists         [][]identitymodel.IdentityUser
	listDepartmentErr error
	listUserErr       error
	upsertDeptErr     error
	upsertDeptAt      int
	upsertDeptN       int
	upsertUserErr     error
	removeErr         error
	statusErr         error
	statusUser        string
	statusValue       identitymodel.IdentityStatus
	profileBindings   []identitymodel.IdentityProfileBinding
	profileBindingErr error
	roleAssignments   []identitymodel.IdentityUserRoleAssignment
	roleAssignmentErr error
	listDepartmentAt  int
	listDepartmentN   int
	listUserAt        int
	listUserN         int
	upsertUserN       int
}

func (r *identityDepartmentUserRepository) ListIdentityUserRoleAssignments(context.Context, string, string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	if r.roleAssignmentErr != nil {
		return nil, r.roleAssignmentErr
	}
	return append([]identitymodel.IdentityUserRoleAssignment(nil), r.roleAssignments...), nil
}

func (r *identityDepartmentUserRepository) ListIdentityProfileBindingsByUser(context.Context, string, string) ([]identitymodel.IdentityProfileBinding, error) {
	return append([]identitymodel.IdentityProfileBinding(nil), r.profileBindings...), r.profileBindingErr
}

func (r *identityDepartmentUserRepository) ListIdentityDepartments(context.Context, string) ([]identitymodel.IdentityDepartment, error) {
	r.listDepartmentN++
	if r.listDepartmentErr != nil && (r.listDepartmentAt == 0 || r.listDepartmentAt == r.listDepartmentN) {
		return nil, r.listDepartmentErr
	}
	if r.listDepartmentN <= len(r.departmentLists) {
		return append([]identitymodel.IdentityDepartment(nil), r.departmentLists[r.listDepartmentN-1]...), nil
	}
	return append([]identitymodel.IdentityDepartment(nil), r.departments...), nil
}

func (r *identityDepartmentUserRepository) UpsertIdentityDepartment(_ context.Context, _ string, department identitymodel.IdentityDepartment) error {
	r.upsertDeptN++
	if r.upsertDeptErr != nil && (r.upsertDeptAt == 0 || r.upsertDeptAt == r.upsertDeptN) {
		return r.upsertDeptErr
	}
	for index := range r.departments {
		if r.departments[index].ID == department.ID {
			r.departments[index] = department
			return nil
		}
	}
	r.departments = append(r.departments, department)
	return nil
}

func (r *identityDepartmentUserRepository) ListIdentityUsers(context.Context, string) ([]identitymodel.IdentityUser, error) {
	r.listUserN++
	if r.listUserErr != nil && (r.listUserAt == 0 || r.listUserAt == r.listUserN) {
		return nil, r.listUserErr
	}
	if r.listUserN <= len(r.userLists) {
		return append([]identitymodel.IdentityUser(nil), r.userLists[r.listUserN-1]...), nil
	}
	return append([]identitymodel.IdentityUser(nil), r.users...), nil
}

func (r *identityDepartmentUserRepository) UpsertIdentityUser(_ context.Context, _ string, user identitymodel.IdentityUser) error {
	r.upsertUserN++
	if r.upsertUserErr != nil {
		return r.upsertUserErr
	}
	for index := range r.users {
		if r.users[index].ID == user.ID {
			r.users[index] = user
			return nil
		}
	}
	r.users = append(r.users, user)
	return nil
}

func (r *identityDepartmentUserRepository) UpsertIdentityUsersAtomically(ctx context.Context, workspace string, users []identitymodel.IdentityUser) error {
	for _, user := range users {
		if err := r.UpsertIdentityUser(ctx, workspace, user); err != nil {
			return err
		}
	}
	return nil
}

func (r *identityDepartmentUserRepository) RemoveIdentityUser(context.Context, string, string) error {
	return r.removeErr
}

func (r *identityDepartmentUserRepository) SetIdentityUserStatus(_ context.Context, _, userID string, status identitymodel.IdentityStatus) error {
	r.statusUser, r.statusValue = userID, status
	return r.statusErr
}

type identityDepartmentUserWorkforceRepository struct {
	*identityDepartmentUserRepository
	identityrepository.IdentityWorkforceRepository
	profiles      []identitymodel.IdentityWorkforceProfile
	assignments   []identitymodel.IdentityWorkforceAssignment
	err           error
	assignmentErr error
}

func (r *identityDepartmentUserWorkforceRepository) ListIdentityWorkforceProfiles(context.Context, string) ([]identitymodel.IdentityWorkforceProfile, error) {
	if r.err != nil {
		return nil, r.err
	}
	return append([]identitymodel.IdentityWorkforceProfile(nil), r.profiles...), nil
}

func (r *identityDepartmentUserWorkforceRepository) GetIdentityWorkforceProfile(_ context.Context, _, profileID string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	if r.err != nil {
		return identitymodel.IdentityWorkforceProfile{}, false, r.err
	}
	for _, profile := range r.profiles {
		if profile.ID == profileID {
			return profile, true, nil
		}
	}
	return identitymodel.IdentityWorkforceProfile{}, false, nil
}

func (r *identityDepartmentUserWorkforceRepository) ListIdentityWorkforceAssignments(_ context.Context, _, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	if r.assignmentErr != nil {
		return nil, r.assignmentErr
	}
	out := make([]identitymodel.IdentityWorkforceAssignment, 0, len(r.assignments))
	for _, assignment := range r.assignments {
		if assignment.WorkforceProfileID == profileID {
			out = append(out, assignment)
		}
	}
	return out, nil
}

func TestIdentityDepartmentLeaderMustBeActiveAndAssignedToDepartment(t *testing.T) {
	profile := identitymodel.IdentityWorkforceProfile{ID: "leader", WorkStatus: identitymodel.IdentityWorkActive}
	assignment := identitymodel.IdentityWorkforceAssignment{
		ID: "leader-primary", WorkforceProfileID: profile.ID, OrganizationUnitID: "sales",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
	}
	for _, test := range []struct {
		name        string
		profiles    []identitymodel.IdentityWorkforceProfile
		assignments []identitymodel.IdentityWorkforceAssignment
		wantError   string
	}{
		{name: "valid leader", profiles: []identitymodel.IdentityWorkforceProfile{profile}, assignments: []identitymodel.IdentityWorkforceAssignment{assignment}},
		{name: "unknown leader", wantError: "backend.identity.department_leader_not_active"},
		{name: "terminated leader", profiles: []identitymodel.IdentityWorkforceProfile{{ID: "leader", WorkStatus: identitymodel.IdentityWorkTerminated}}, wantError: "backend.identity.department_leader_not_active"},
		{name: "leader assigned elsewhere", profiles: []identitymodel.IdentityWorkforceProfile{profile}, assignments: []identitymodel.IdentityWorkforceAssignment{{ID: "other", WorkforceProfileID: "leader", OrganizationUnitID: "ops", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive}}, wantError: "backend.identity.department_leader_assignment_required"},
		{name: "inactive assignment", profiles: []identitymodel.IdentityWorkforceProfile{profile}, assignments: []identitymodel.IdentityWorkforceAssignment{{ID: "inactive", WorkforceProfileID: "leader", OrganizationUnitID: "sales", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusDisabled}}, wantError: "backend.identity.department_leader_assignment_required"},
		{name: "secondary assignment", profiles: []identitymodel.IdentityWorkforceProfile{profile}, assignments: []identitymodel.IdentityWorkforceAssignment{{ID: "secondary", WorkforceProfileID: "leader", OrganizationUnitID: "sales", AssignmentType: identitymodel.IdentityWorkforceAssignmentSecondary, Status: identitymodel.IdentityStatusActive}}, wantError: "backend.identity.department_leader_assignment_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &identityDepartmentUserWorkforceRepository{
				identityDepartmentUserRepository: &identityDepartmentUserRepository{}, profiles: test.profiles, assignments: test.assignments,
			}
			service := NewIdentityDomainService(repository, nil)
			err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "sales", Name: "Sales", LeaderWorkforceProfileID: "leader"})
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error=%v want %s", err, test.wantError)
			}
		})
	}
	withoutWorkforce := NewIdentityDomainService(&identityDepartmentUserRepository{}, nil)
	if err := withoutWorkforce.validateDepartmentLeader(t.Context(), identitymodel.IdentityDepartment{ID: "sales", LeaderWorkforceProfileID: "leader"}); apperror.CodeOf(err) != "backend.identity.workforce_unavailable" {
		t.Fatalf("capability error=%v", err)
	}
	getErrRepository := &identityDepartmentUserWorkforceRepository{identityDepartmentUserRepository: &identityDepartmentUserRepository{}, err: errIdentityDepartmentUserEdge}
	if err := NewIdentityDomainService(getErrRepository, nil).validateDepartmentLeader(t.Context(), identitymodel.IdentityDepartment{ID: "sales", LeaderWorkforceProfileID: "leader"}); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("get error=%v", err)
	}
	assignmentErrRepository := &identityDepartmentUserWorkforceRepository{identityDepartmentUserRepository: &identityDepartmentUserRepository{}, profiles: []identitymodel.IdentityWorkforceProfile{profile}, assignmentErr: errIdentityDepartmentUserEdge}
	if err := NewIdentityDomainService(assignmentErrRepository, nil).validateDepartmentLeader(t.Context(), identitymodel.IdentityDepartment{ID: "sales", LeaderWorkforceProfileID: "leader"}); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("assignment error=%v", err)
	}
}

func TestIdentityDepartmentPathRebuildUpdatesDescendantsOnly(t *testing.T) {
	repository := &identityDepartmentUserRepository{departments: []identitymodel.IdentityDepartment{
		{ID: "root", Path: "/root"}, {ID: "child", Path: "/root/child/"}, {ID: "other", Path: "/other"},
	}}
	service := NewIdentityDomainService(repository, nil)
	if err := service.rebuildDepartmentPathReferences(t.Context(), "/root/", "/company/root/", repository.departments); err != nil {
		t.Fatal(err)
	}
	if repository.departments[1].Path != "/company/root/child" || repository.departments[2].Path != "/other" {
		t.Fatalf("departments=%+v", repository.departments)
	}
	for _, paths := range [][2]string{{"", "/new"}, {"/old", ""}, {"/same", "/same/"}} {
		if err := service.rebuildDepartmentPathReferences(t.Context(), paths[0], paths[1], nil); err != nil {
			t.Fatalf("short circuit %q -> %q: %v", paths[0], paths[1], err)
		}
	}
	repository.upsertDeptErr = errIdentityDepartmentUserEdge
	repository.departments[1].Path = "/old/child"
	if err := service.rebuildDepartmentPathReferences(t.Context(), "/old", "/new", repository.departments); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("department error=%v", err)
	}
}

func TestIdentityUserLookupAndRemovalEdges(t *testing.T) {
	repository := &identityDepartmentUserRepository{users: []identitymodel.IdentityUser{{ID: " manager ", Email: "Manager@Example.com"}}}
	service := NewIdentityDomainService(repository, nil)
	if _, found, err := service.UserByLogin(t.Context(), " "); err != nil || found {
		t.Fatalf("empty login found=%v error=%v", found, err)
	}
	if user, found, err := service.UserByLogin(t.Context(), "manager@example.com"); err != nil || !found || user.Email != "Manager@Example.com" {
		t.Fatalf("email lookup=%+v found=%v error=%v", user, found, err)
	}
	repository.listUserErr = errIdentityDepartmentUserEdge
	if _, _, err := service.UserByLogin(t.Context(), "manager"); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("lookup error=%v", err)
	}
	repository.listUserErr = nil
	if err := service.RemoveUser(t.Context(), " "); err == nil {
		t.Fatal("empty user removal accepted")
	}
	repository.profileBindingErr = errIdentityDepartmentUserEdge
	if err := service.RemoveUser(t.Context(), "user"); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("profile binding lookup error=%v", err)
	}
	repository.profileBindingErr = nil
	repository.profileBindings = []identitymodel.IdentityProfileBinding{{ObjectKey: "member_profile", ProfileID: "member-1"}}
	if err := service.RemoveUser(t.Context(), "user"); err == nil || !strings.Contains(err.Error(), "backend.identity.user_profile_bindings_exist") || apperror.ParamsOf(err)["profiles"] != "member_profile:member-1" {
		t.Fatalf("bound user deletion error=%v", err)
	}
	repository.profileBindings = nil
	repository.removeErr = errIdentityDepartmentUserEdge
	if err := service.RemoveUser(t.Context(), "user"); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("remove error=%v", err)
	}
}

func TestIdentityUserDeletionImpactEnumeratesProfileAndEntitlementFacts(t *testing.T) {
	repository := &identityDepartmentUserRepository{
		users: []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
		profileBindings: []identitymodel.IdentityProfileBinding{{
			ObjectKey: "member_profile", ProfileID: "member-1", IdentityUserID: "user", Status: identitymodel.IdentityProfileBindingActive,
		}},
		roleAssignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "user", RoleID: "active", Status: "active"},
			{UserID: "user", RoleID: "revoked", Status: "revoked"},
		},
	}
	service := NewIdentityDomainService(repository, nil)
	impact, err := service.UserDeletionImpact(t.Context(), " user ")
	if err != nil || impact.UserID != "user" || impact.CanDelete || !impact.CredentialsAndSessionsRevoked ||
		len(impact.ProfileBindings) != 1 || len(impact.ActiveRoleIDs) != 1 || impact.ActiveRoleIDs[0] != "active" {
		t.Fatalf("impact=%+v err=%v", impact, err)
	}
}

func TestIdentityDirectoryListAndUserStatusDelegation(t *testing.T) {
	repository := &identityDepartmentUserRepository{
		departments: []identitymodel.IdentityDepartment{{ID: "department"}},
		users:       []identitymodel.IdentityUser{{ID: "user"}},
	}
	service := NewIdentityDomainService(repository, nil)
	if departments, err := service.ListDepartments(t.Context()); err != nil || len(departments) != 1 {
		t.Fatalf("departments=%+v err=%v", departments, err)
	}
	if users, err := service.ListUsers(t.Context()); err != nil || len(users) != 1 {
		t.Fatalf("users=%+v err=%v", users, err)
	}
	if err := service.SetUserStatus(t.Context(), "user", identitymodel.IdentityStatusDisabled); err != nil || repository.statusUser != "user" || repository.statusValue != identitymodel.IdentityStatusDisabled {
		t.Fatalf("status user=%q value=%q err=%v", repository.statusUser, repository.statusValue, err)
	}
	repository.listDepartmentErr = errIdentityDepartmentUserEdge
	if _, err := service.ListDepartments(t.Context()); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("list departments error=%v", err)
	}
	repository.listDepartmentErr = nil
	repository.listUserErr = errIdentityDepartmentUserEdge
	if _, err := service.ListUsers(t.Context()); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("list users error=%v", err)
	}
	repository.statusErr = errIdentityDepartmentUserEdge
	if err := service.SetUserStatus(t.Context(), "user", identitymodel.IdentityStatusActive); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("set status error=%v", err)
	}
}

func TestUpsertDepartmentBuildsAndRebuildsHierarchyPaths(t *testing.T) {
	repository := &identityDepartmentUserRepository{users: []identitymodel.IdentityUser{{ID: "account", Name: "Account", Email: "account@example.com"}}}
	service := NewIdentityDomainService(repository, nil)
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: " root ", Name: " Root "}); err != nil {
		t.Fatal(err)
	}
	root := "root"
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "child", Name: "Child", ParentID: &root}); err != nil {
		t.Fatal(err)
	}
	if got := repository.departments[1]; got.Path != "/root/child" || got.Depth != 1 || !reflect.DeepEqual(got.AncestorIDs, []string{"root"}) {
		t.Fatalf("child=%+v", got)
	}
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "other", Name: "Other"}); err != nil {
		t.Fatal(err)
	}
	child, other := "child", "other"
	repository.departments = append(repository.departments, identitymodel.IdentityDepartment{ID: "grandchild", Name: "Grandchild", ParentID: &child, Path: "/root/child/grandchild", AncestorIDs: []string{"root", "child"}, Depth: 2})
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "child", Name: "Child", ParentID: &other, Path: "/root/child"}); err != nil {
		t.Fatal(err)
	}
	if repository.departments[1].Path != "/other/child" || repository.departments[3].Path != "/other/child/grandchild" {
		t.Fatalf("moved departments=%+v", repository.departments)
	}
	if repository.listUserN != 0 || repository.upsertUserN != 0 || repository.users[0].ID != "account" {
		t.Fatalf("department move touched identity users: list=%d upsert=%d users=%+v", repository.listUserN, repository.upsertUserN, repository.users)
	}
}

func TestUpsertDepartmentAndAccountValidationWriteFailures(t *testing.T) {
	repository := &identityDepartmentUserRepository{}
	service := NewIdentityDomainService(repository, nil)
	for _, department := range []identitymodel.IdentityDepartment{{Name: "Department"}, {ID: "department"}} {
		if err := service.UpsertDepartment(t.Context(), department); err == nil {
			t.Fatal("invalid department accepted")
		}
	}
	repository.upsertDeptErr = errIdentityDepartmentUserEdge
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{ID: "department", Name: "Department"}); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("department upsert error=%v", err)
	}
	repository.upsertDeptErr = nil
	for _, user := range []identitymodel.IdentityUser{
		{Name: "User", Email: "user@example.com"}, {ID: "unsafe/id", Name: "User", Email: "user@example.com"},
		{ID: "user", Email: "user@example.com"}, {ID: "user", Name: "User"}, {ID: "user", Name: "User", Email: "invalid"},
	} {
		if err := service.UpsertUser(t.Context(), user); err == nil {
			t.Fatalf("invalid account accepted: %#v", user)
		}
	}
	repository.upsertUserErr = errIdentityDepartmentUserEdge
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{ID: "user", Name: "User", Email: "user@example.com"}); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("account write error=%v", err)
	}
}

func TestUpsertUserNormalizesAccountOnly(t *testing.T) {
	repository := &identityDepartmentUserRepository{}
	service := NewIdentityDomainService(repository, nil)
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{
		ID: " employee ", Name: " Employee ", Email: " EMPLOYEE@EXAMPLE.COM ", Phone: " 123 ",
	}); err != nil {
		t.Fatal(err)
	}
	if len(repository.users) != 1 {
		t.Fatalf("users=%#v", repository.users)
	}
	account := repository.users[0]
	if account.ID != "employee" || account.Name != "Employee" || account.Email != "employee@example.com" || account.Phone != "123" {
		t.Fatalf("normalized account=%+v", account)
	}
}

func TestUpsertDepartmentPropagatesSnapshotsNormalizesEmptyParentAndStopsAtMissingAncestor(t *testing.T) {
	valid := identitymodel.IdentityDepartment{ID: "department", Name: "Department"}
	repository := &identityDepartmentUserRepository{
		listDepartmentErr: errIdentityDepartmentUserEdge,
		listDepartmentAt:  1,
	}
	if err := NewIdentityDomainService(repository, nil).UpsertDepartment(t.Context(), valid); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("validation snapshot error=%v", err)
	}

	repository = &identityDepartmentUserRepository{
		listDepartmentErr: errIdentityDepartmentUserEdge,
		listDepartmentAt:  2,
	}
	if err := NewIdentityDomainService(repository, nil).UpsertDepartment(t.Context(), valid); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("write snapshot error=%v", err)
	}

	emptyParent := " "
	repository = &identityDepartmentUserRepository{}
	if err := NewIdentityDomainService(repository, nil).UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{
		ID: "department", Name: "Department", ParentID: &emptyParent,
	}); err != nil {
		t.Fatal(err)
	}
	if len(repository.departments) != 1 || repository.departments[0].ParentID != nil || repository.departments[0].Path != "/department" {
		t.Fatalf("normalized department=%+v", repository.departments)
	}

	missingAncestor, parentID := "missing", "parent"
	repository = &identityDepartmentUserRepository{departments: []identitymodel.IdentityDepartment{{
		ID: "parent", Name: "Parent", ParentID: &missingAncestor, Path: "/parent",
	}}}
	if err := NewIdentityDomainService(repository, nil).UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{
		ID: "child", Name: "Child", ParentID: &parentID,
	}); err != nil {
		t.Fatal(err)
	}
	if child := repository.departments[1]; child.Path != "/parent/child" || child.Depth != 1 {
		t.Fatalf("child with missing ancestor=%+v", child)
	}
}

func TestUpsertDepartmentPropagatesDescendantRebuildFailure(t *testing.T) {
	newParentID := "new-parent"
	repository := &identityDepartmentUserRepository{
		departments: []identitymodel.IdentityDepartment{
			{ID: "old-parent", Name: "Old Parent", Path: "/old-parent"},
			{ID: "new-parent", Name: "New Parent", Path: "/new-parent"},
			{ID: "moving", Name: "Moving", ParentID: identityStringPointer("old-parent"), Path: "/old-parent/moving", AncestorIDs: []string{"old-parent"}, Depth: 1},
			{ID: "child", Name: "Child", ParentID: identityStringPointer("moving"), Path: "/old-parent/moving/child", AncestorIDs: []string{"old-parent", "moving"}, Depth: 2},
		},
		upsertDeptErr: errIdentityDepartmentUserEdge,
		upsertDeptAt:  2,
	}
	err := NewIdentityDomainService(repository, nil).UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{
		ID: "moving", Name: "Moving", ParentID: &newParentID, Path: "/old-parent/moving",
	})
	if !errors.Is(err, errIdentityDepartmentUserEdge) || repository.upsertDeptN != 2 {
		t.Fatalf("rebuild error=%v upserts=%d", err, repository.upsertDeptN)
	}
}

func TestPrepareUserSecondSnapshotAndDeletionImpactFailureMatrix(t *testing.T) {
	validUser := identitymodel.IdentityUser{ID: "user", Name: "User", Email: "user@example.com"}
	repository := &identityDepartmentUserRepository{
		listUserErr: errIdentityDepartmentUserEdge,
		listUserAt:  2,
	}
	if err := NewIdentityDomainService(repository, nil).UpsertUser(t.Context(), validUser); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("second user snapshot error=%v", err)
	}

	service := NewIdentityDomainService(&identityDepartmentUserRepository{}, nil)
	if _, err := service.UserDeletionImpact(t.Context(), " "); apperror.CodeOf(err) != "backend.identity.user_required" {
		t.Fatalf("empty user impact error=%v", err)
	}

	repository = &identityDepartmentUserRepository{
		users:             []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
		profileBindingErr: errIdentityDepartmentUserEdge,
	}
	service = NewIdentityDomainService(repository, nil)
	if _, err := service.UserDeletionImpact(t.Context(), "user"); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("profile binding impact error=%v", err)
	}

	repository.profileBindingErr = nil
	repository.roleAssignmentErr = errIdentityDepartmentUserEdge
	if _, err := service.UserDeletionImpact(t.Context(), "user"); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("role assignment impact error=%v", err)
	}

	workforceRepository := &identityDepartmentUserWorkforceRepository{
		identityDepartmentUserRepository: &identityDepartmentUserRepository{
			users: []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
		},
		err: errIdentityDepartmentUserEdge,
	}
	service = NewIdentityDomainService(workforceRepository, nil)
	if _, err := service.UserDeletionImpact(t.Context(), "user"); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("workforce impact error=%v", err)
	}
}

func TestUserDeletionImpactSortsBindingsAndFiltersWorkforceProfiles(t *testing.T) {
	repository := &identityDepartmentUserWorkforceRepository{
		identityDepartmentUserRepository: &identityDepartmentUserRepository{
			users: []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
			profileBindings: []identitymodel.IdentityProfileBinding{
				{ObjectKey: "z_profile", ProfileID: "z", IdentityUserID: "user"},
				{ObjectKey: "a_profile", ProfileID: "z", IdentityUserID: "user"},
				{ObjectKey: "a_profile", ProfileID: "a", IdentityUserID: "user"},
			},
		},
		profiles: []identitymodel.IdentityWorkforceProfile{
			{ID: "outside", IdentityUserID: "other"},
			{ID: "workforce-b", IdentityUserID: "user"},
			{ID: "workforce-a", IdentityUserID: "user"},
		},
	}
	impact, err := NewIdentityDomainService(repository, nil).UserDeletionImpact(t.Context(), "user")
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{
		impact.ProfileBindings[0].ObjectKey + ":" + impact.ProfileBindings[0].ProfileID,
		impact.ProfileBindings[1].ObjectKey + ":" + impact.ProfileBindings[1].ProfileID,
		impact.ProfileBindings[2].ObjectKey + ":" + impact.ProfileBindings[2].ProfileID,
	}; !reflect.DeepEqual(got, []string{"a_profile:a", "a_profile:z", "z_profile:z"}) {
		t.Fatalf("sorted bindings=%v", got)
	}
	if !reflect.DeepEqual(impact.WorkforceProfileIDs, []string{"workforce-a", "workforce-b"}) {
		t.Fatalf("workforce profiles=%v", impact.WorkforceProfileIDs)
	}
}

func TestIdentityDepartmentAndUserRemainingConditionOutcomes(t *testing.T) {
	repository := &identityDepartmentUserRepository{}
	service := NewIdentityDomainService(repository, nil)
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{
		ID: "explicit-status", Name: "Explicit Status", Status: identitymodel.IdentityStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	blankParent := " "
	repository = &identityDepartmentUserRepository{departments: []identitymodel.IdentityDepartment{{
		ID: "parent", Name: "Parent", ParentID: &blankParent, Path: "/parent",
	}}}
	parentID := "parent"
	service = NewIdentityDomainService(repository, nil)
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{
		ID: "child", Name: "Child", ParentID: &parentID,
	}); err != nil {
		t.Fatal(err)
	}

	repository = &identityDepartmentUserRepository{departments: []identitymodel.IdentityDepartment{{
		ID: "stable", Name: "Stable", Path: "/stable",
	}}}
	service = NewIdentityDomainService(repository, nil)
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{
		ID: "stable", Name: "Stable", Path: "/stable",
	}); err != nil {
		t.Fatal(err)
	}

	repository = &identityDepartmentUserRepository{departments: []identitymodel.IdentityDepartment{{
		ID: "empty-old-path", Name: "Empty Old Path",
	}}}
	service = NewIdentityDomainService(repository, nil)
	if err := service.UpsertDepartment(t.Context(), identitymodel.IdentityDepartment{
		ID: "empty-old-path", Name: "Empty Old Path", Path: "/empty-old-path",
	}); err != nil {
		t.Fatal(err)
	}

	repository = &identityDepartmentUserRepository{users: []identitymodel.IdentityUser{{
		ID: "user-id", Name: "User", Email: "other@example.com", Status: identitymodel.IdentityStatusActive,
	}}}
	service = NewIdentityDomainService(repository, nil)
	if user, found, err := service.UserByID(t.Context(), " user-id "); err != nil || !found || user.ID != "user-id" {
		t.Fatalf("user by id=%+v found=%v err=%v", user, found, err)
	}
	if user, found, err := service.UserByLogin(t.Context(), "USER-ID"); err != nil || !found || user.ID != "user-id" {
		t.Fatalf("user login by id=%+v found=%v err=%v", user, found, err)
	}
	if user, found, err := service.UserByLogin(t.Context(), "missing-login"); err != nil || found || user.ID != "" {
		t.Fatalf("missing user login=%+v found=%v err=%v", user, found, err)
	}
	if err := service.UpsertUser(t.Context(), identitymodel.IdentityUser{
		ID: "service-user", Name: "Service User", Email: "service@example.com",
		AccountType: identitymodel.IdentityAccountService,
	}); err != nil {
		t.Fatal(err)
	}

	repository = &identityDepartmentUserRepository{
		users:       []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
		listUserErr: errIdentityDepartmentUserEdge,
	}
	service = NewIdentityDomainService(repository, nil)
	if _, err := service.UserDeletionImpact(t.Context(), "user"); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("deletion user lookup error=%v", err)
	}
	repository.listUserErr = nil
	repository.users = nil
	if _, err := service.UserDeletionImpact(t.Context(), "missing"); apperror.CodeOf(err) != "backend.identity.user_not_found" {
		t.Fatalf("missing deletion user error=%v", err)
	}
}
