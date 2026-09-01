package service

import (
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func TestListAssignableWorkforceRoleEdges(t *testing.T) {
	withoutRepository, err := NewIdentityDomainService(nil, nil).ForWorkspace("workspace")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutRepository.ListAssignableWorkforceRoles(t.Context(), "profile", identitymodel.Principal{}); apperror.CodeOf(err) != "backend.internal" {
		t.Fatalf("missing workforce repository error=%v", err)
	}

	repository, service := identityRolesFixture()
	repository.err = errIdentityRolesRepository
	if _, err := service.ListAssignableWorkforceRoles(t.Context(), "profile", identitymodel.Principal{}); err != errIdentityRolesRepository {
		t.Fatalf("workforce lookup error=%v", err)
	}
	repository.err = nil
	repository.workforceProfiles = []identitymodel.IdentityWorkforceProfile{{ID: "inactive", IdentityUserID: "user-1", WorkStatus: identitymodel.IdentityWorkTerminated}}
	if roles, err := service.ListAssignableWorkforceRoles(t.Context(), "inactive", identitymodel.Principal{}); err != nil || len(roles) != 0 {
		t.Fatalf("inactive roles=%v error=%v", roles, err)
	}
	repository.workforceProfiles = []identitymodel.IdentityWorkforceProfile{{ID: "active", IdentityUserID: "user-1", WorkStatus: identitymodel.IdentityWorkActive}}
	repository.listUsersErr = errIdentityRolesRepository
	if _, err := service.ListAssignableWorkforceRoles(t.Context(), "active", identitymodel.Principal{Known: true, UserID: "admin", Role: identitymodel.RoleSchema{RecordScope: "all_records"}}); err != errIdentityRolesRepository {
		t.Fatalf("assignable roles error=%v", err)
	}
}

func TestIdentityActorRoleTargetScopeEdges(t *testing.T) {
	target := identityWorkforceFacts{DepartmentID: "department", DepartmentPath: "/company/sales/east"}
	if identityActorCanManageRoleTarget(identitymodel.Principal{}, "user", target) ||
		identityActorCanManageRoleTarget(identitymodel.Principal{Known: true, UserID: " "}, "user", target) {
		t.Fatal("unknown actor managed role target")
	}
	for _, actor := range []identitymodel.Principal{
		{Known: true, UserID: "admin", Role: identitymodel.RoleSchema{RecordScope: "all_records"}},
		{Known: true, UserID: "user"},
		{Known: true, UserID: "manager", ReportingUserIDs: []string{"user"}, Role: identitymodel.RoleSchema{RecordScope: "subordinates"}},
		{Known: true, UserID: "manager", DepartmentID: "department", Role: identitymodel.RoleSchema{RecordScope: "department"}},
		{Known: true, UserID: "manager", DepartmentPath: "/company/sales/", Role: identitymodel.RoleSchema{RecordScope: "department_and_children"}},
	} {
		if !identityActorCanManageRoleTarget(actor, "user", target) {
			t.Fatalf("actor=%+v was denied", actor)
		}
	}
	if identityActorCanManageRoleTarget(identitymodel.Principal{Known: true, UserID: "admin", Role: identitymodel.RoleSchema{Permissions: []string{"identity.roles.list"}}}, "user", target) {
		t.Fatal("functional Permission expanded into role-target data scope")
	}
	if identityActorCanManageRoleTarget(identitymodel.Principal{Known: true, UserID: "manager", Role: identitymodel.RoleSchema{RecordScope: "none"}}, "user", target) {
		t.Fatal("unsupported scope managed target")
	}
}

func TestIdentityRequestableRoleAssignmentModeEdges(t *testing.T) {
	repository, service := identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged},
		{Key: "viewer", AssignmentMode: identitymodel.IdentityRoleAssignmentRequestOnly},
		{Key: "admin", AssignmentMode: identitymodel.IdentityRoleAssignmentRequestOnly},
	})
	roles, err := service.ListRequestableRoles(t.Context())
	if err != nil || len(roles) != 2 {
		t.Fatalf("requestable roles=%v error=%v", roles, err)
	}
	repository.listRolesErr = errIdentityRolesRepository
	if _, err := service.ListRequestableRoles(t.Context()); err != errIdentityRolesRepository {
		t.Fatalf("requestable lookup error=%v", err)
	}
}

type identityRoleRequestNoDecisionRepository struct {
	identityrepository.IdentityRepository
}

func TestIdentityRoleRequestDecisionAndApprovalEdges(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request", UserID: "user-1", RequestedBy: "maker", RoleIDs: []string{"member-id"}, Status: "pending"}}
	if _, err := service.ApproveRoleRequest(t.Context(), "request", " ", ""); apperror.CodeOf(err) != "backend.identity.role_request_self_approval_denied" {
		t.Fatalf("empty reviewer error=%v", err)
	}
	repository.listRolesErr = errIdentityRolesRepository
	if _, err := service.ApproveRoleRequest(t.Context(), "request", "reviewer", ""); err != errIdentityRolesRepository {
		t.Fatalf("role lookup error=%v", err)
	}

	repository, service = identityRolesFixture()
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request", UserID: "user-1", RoleIDs: []string{"missing"}, Status: "pending"}}
	if _, err := service.ApproveRoleRequest(t.Context(), "request", "reviewer", ""); apperror.CodeOf(err) != "backend.identity.role_not_found" {
		t.Fatalf("missing role error=%v", err)
	}

	repository, service = identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged}})
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request", UserID: "user-1", RoleIDs: []string{"member-id"}, Status: "pending"}}
	if _, err := service.ApproveRoleRequest(t.Context(), "request", "reviewer", ""); apperror.CodeOf(err) != "backend.identity.system_managed_role_assignment_denied" {
		t.Fatalf("system role error=%v", err)
	}

	repository, service = identityRolesFixture()
	service.ReplaceRoleDefinitions(nil)
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request", UserID: "user-1", RoleIDs: []string{"member-id"}, Status: "pending"}}
	if approved, err := service.ApproveRoleRequest(t.Context(), "request", "reviewer", ""); err != nil || approved.Status != "approved" {
		t.Fatalf("unpublished fallback approval=%+v error=%v", approved, err)
	}

	repository, service = identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "member", Audience: identitymodel.IdentityRoleAudienceWorkforce, AssignmentMode: identitymodel.IdentityRoleAssignmentManual}})
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request", UserID: "user-1", RoleIDs: []string{"member-id"}, Status: "pending"}}
	if _, err := service.ApproveRoleRequest(t.Context(), "request", "reviewer", ""); apperror.CodeOf(err) != "backend.identity.workforce_role_eligibility_required" {
		t.Fatalf("workforce eligibility error=%v", err)
	}

	repository, service = identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentRequestOnly, RiskLevel: identitymodel.IdentityRoleRiskElevated}})
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request", UserID: "user-1", RequestedBy: "maker", RoleIDs: []string{"member-id"}, Status: "pending"}}
	if _, err := service.ApproveRoleRequest(t.Context(), "request", "reviewer", "", identitymodel.Principal{UserID: "reviewer"}); apperror.CodeOf(err) != "backend.identity.role_request_reviewer_principal_required" {
		t.Fatalf("unknown reviewer error=%v", err)
	}
	approved, err := service.ApproveRoleRequest(t.Context(), "request", "reviewer", "", identitymodel.Principal{Known: true, UserID: "reviewer", Role: identitymodel.RoleSchema{GrantableRoleKeys: []string{"*"}}})
	if err != nil || approved.Status != "approved" {
		t.Fatalf("wildcard approval=%+v error=%v", approved, err)
	}

	repository, service = identityRolesFixture()
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request", UserID: "user-1", RoleIDs: []string{"member-id"}, Status: "pending"}}
	repository.listAssignmentsErr = errIdentityRolesRepository
	if _, err := service.ApproveRoleRequest(t.Context(), "request", "reviewer", ""); err != errIdentityRolesRepository {
		t.Fatalf("assignment listing error=%v", err)
	}

	repository, service = identityRolesFixture()
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request", UserID: "user-1", RoleIDs: []string{"member-id"}, Status: "pending"}}
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{{UserID: "other", RoleID: "viewer-id", Status: "active"}}
	if approved, err := service.ApproveRoleRequest(t.Context(), "request", "reviewer", ""); err != nil || approved.Status != "approved" {
		t.Fatalf("approval with current assignment=%+v error=%v", approved, err)
	}

	for _, failCall := range []int{2, 3, 4} {
		repository, service = identityRolesFixture()
		roles := append([]identitymodel.IdentityRole(nil), repository.roles...)
		repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request", UserID: "user-1", RoleIDs: []string{"member-id"}, Status: "pending"}}
		repository.listRolesFunc = func(call int) ([]identitymodel.IdentityRole, error) {
			if call == failCall {
				return nil, errIdentityRolesRepository
			}
			return roles, nil
		}
		_, _ = service.ApproveRoleRequest(t.Context(), "request", "reviewer", "")
	}

	repository, base := identityRolesFixture()
	noDecision, err := NewIdentityDomainService(identityRoleRequestNoDecisionRepository{IdentityRepository: repository}, nil).ForWorkspace("workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	noDecision.ReplaceRoleDefinitions(base.PublishedRoleDefinitions(t.Context()))
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request", UserID: "user-1", RoleIDs: []string{"member-id"}, Status: "pending"}}
	if _, err := noDecision.ApproveRoleRequest(t.Context(), "request", "reviewer", ""); apperror.CodeOf(err) != "backend.internal" {
		t.Fatalf("missing approval decision repository error=%v", err)
	}
	if _, err := noDecision.RejectRoleRequest(t.Context(), "request", "reviewer", ""); apperror.CodeOf(err) != "backend.internal" {
		t.Fatalf("missing rejection decision repository error=%v", err)
	}
}

func TestIdentityAssignmentActivityAndPrivilegedRoleEdges(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Hour).Format(time.RFC3339)
	past := now.Add(-time.Hour).Format(time.RFC3339)
	for _, assignment := range []identitymodel.IdentityUserRoleAssignment{
		{ValidFrom: "invalid"},
		{ValidFrom: future},
		{ValidUntil: "invalid"},
		{ValidUntil: past},
	} {
		if identityAssignmentActive(assignment, now) {
			t.Fatalf("inactive assignment accepted: %+v", assignment)
		}
	}
	if !identityAssignmentActive(identitymodel.IdentityUserRoleAssignment{ValidFrom: past, ValidUntil: future}, now) {
		t.Fatal("bounded active assignment rejected")
	}
	repository, service := identityRolesFixture()
	if service.identityPrivilegedAutoAssignableRole(identitymodel.IdentityRole{Key: "unpublished"}) {
		t.Fatal("unpublished role was privileged")
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "member", Permissions: []string{"other", " identity.roles.list "}, RiskLevel: identitymodel.IdentityRoleRiskPrivileged}})
	if !service.identityPrivilegedAutoAssignableRole(identitymodel.IdentityRole{ID: "member-id", Key: "member"}) {
		t.Fatal("published privileged risk level was not enforced")
	}
	repository.roles = nil
}
