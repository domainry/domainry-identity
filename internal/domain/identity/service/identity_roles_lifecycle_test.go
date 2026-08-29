package service

import (
	"context"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityRoleBindingEligibilityStub struct {
	active bool
	err    error
}

func (s identityRoleBindingEligibilityStub) IdentityRoleBindingActive(context.Context, string, string, string, string) (bool, error) {
	return s.active, s.err
}

func TestIdentitySearchRolesNormalizesPaginationAndFields(t *testing.T) {
	repository, service := identityRolesFixture()
	listed, err := service.ListRoles(t.Context())
	if err != nil || len(listed) != len(repository.roles) {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
	page, err := service.SearchRoles(t.Context(), identitymodel.IdentityListQuery{Search: "view", SearchFields: []string{"key"}, PageSize: 500})
	if err != nil || page.PageSize != 200 || page.Total != 1 || page.Items[0].Key != "viewer" || page.HasNext {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	page, err = service.SearchRoles(t.Context(), identitymodel.IdentityListQuery{Search: "member", SearchFields: []string{"description"}})
	if err != nil || page.PageSize != 20 || len(page.Items) != 0 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if _, err := service.SearchRoles(t.Context(), identitymodel.IdentityListQuery{SearchFields: []string{"unknown"}}); apperror.CodeOf(err) != "backend.identity.role_search_field_invalid" {
		t.Fatalf("expected field error, got %v", err)
	}
	page, err = service.SearchRoles(t.Context(), identitymodel.IdentityListQuery{Search: "member"})
	if err != nil || page.Total != 1 || page.Items[0].ID != "member-id" {
		t.Fatalf("default fields page=%#v err=%v", page, err)
	}
	page, err = service.SearchRoles(t.Context(), identitymodel.IdentityListQuery{PageSize: 1})
	if err != nil || !page.HasNext {
		t.Fatalf("expected next page: %#v err=%v", page, err)
	}
	repository.err = errIdentityRolesRepository
	if _, err := service.SearchRoles(t.Context(), identitymodel.IdentityListQuery{}); err != errIdentityRolesRepository {
		t.Fatalf("expected repository error, got %v", err)
	}
}

func TestIdentityActiveRolesForUserFiltersAndSorts(t *testing.T) {
	repository, service := identityRolesFixture()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	invalid := "invalid"
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{
		{UserID: "user-1", RoleID: "viewer-id"},
		{UserID: "user-1", RoleID: "member-id", ExpiresAt: &future},
		{UserID: "user-1", RoleID: "admin-id", ExpiresAt: &past},
		{UserID: "user-1", RoleID: "owner-id", ExpiresAt: &invalid},
		{UserID: "user-1", RoleID: "disabled-id"},
	}
	roles, err := service.ActiveRolesForUser(t.Context(), "user-1")
	if err != nil || len(roles) != 2 || roles[0].ID != "member-id" || roles[1].ID != "viewer-id" {
		t.Fatalf("roles=%#v err=%v", roles, err)
	}
	repository.err = errIdentityRolesRepository
	if _, err := service.ActiveRolesForUser(t.Context(), "user-1"); err != errIdentityRolesRepository {
		t.Fatalf("expected assignment error, got %v", err)
	}
	repository.err = nil
	repository.listRolesErr = errIdentityRolesRepository
	if _, err := service.ActiveRolesForUser(t.Context(), "user-1"); err != errIdentityRolesRepository {
		t.Fatalf("expected role list error, got %v", err)
	}
}

func TestIdentityRoleAssignmentRemoval(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "member-id", Status: "active"}}
	if err := service.RemoveUserRoleGoverned(t.Context(), "user-1", "member-id", "admin-1", "access review"); err != nil {
		t.Fatal(err)
	}
	if len(repository.assigned) != 1 ||
		repository.assigned[0].Status != "revoked" ||
		repository.assigned[0].RevokedBy != "admin-1" ||
		repository.assigned[0].RevokeReason != "access review" ||
		repository.assigned[0].RevokedAt == "" {
		t.Fatalf("revoked assignment=%#v", repository.assigned)
	}
	repository.assignments = nil
	if err := service.RemoveUserRole(t.Context(), "user-1", "member-id"); err != nil || repository.removedUser != "user-1" || repository.removedUserRole != "member-id" {
		t.Fatalf("remove assignment failed: %v %#v", err, repository)
	}
}

func TestIdentityListAssignableRolesExcludesPrivilegedAndInactive(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.roles = append(repository.roles, identitymodel.IdentityRole{ID: "member-b", Key: "member_b", Label: "Member", Status: identitymodel.IdentityStatusActive})
	definitions := service.PublishedRoleDefinitions(t.Context())
	service.ReplaceRoleDefinitions(append(definitions, identitymodel.RoleSchema{Key: "member_b", Name: "Member", RecordScope: "all_records"}))
	actor := identitymodel.Principal{Known: true, UserID: "admin", Role: identitymodel.RoleSchema{RecordScope: "all_records"}}
	roles, err := service.ListAssignableRoles(t.Context(), "user-1", actor)
	if err != nil || len(roles) != 3 || roles[0].Key != "member" || roles[1].Key != "member_b" || roles[2].Key != "viewer" {
		t.Fatalf("roles=%#v err=%v", roles, err)
	}
	repository.err = errIdentityRolesRepository
	if _, err := service.ListAssignableRoles(t.Context(), "user-1", actor); err != errIdentityRolesRepository {
		t.Fatalf("expected repository error, got %v", err)
	}
}

func TestIdentityListAssignableRolesFiltersTargetCeilingAndOrganization(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.roles = []identitymodel.IdentityRole{
		{ID: "general-id", Key: "general", Label: "General", Status: identitymodel.IdentityStatusActive},
		{ID: "employee-id", Key: "employee", Label: "Employee", Status: identitymodel.IdentityStatusActive},
		{ID: "member-id", Key: "member", Label: "Member", Status: identitymodel.IdentityStatusActive},
		{ID: "elevated-id", Key: "elevated", Label: "Elevated", Status: identitymodel.IdentityStatusActive},
		{ID: "service-id", Key: "service", Label: "Service", Status: identitymodel.IdentityStatusActive},
	}
	repository.users = append(repository.users, identitymodel.IdentityUser{ID: "member-only", Status: identitymodel.IdentityStatusActive})
	repository.workforceProfiles = []identitymodel.IdentityWorkforceProfile{{
		ID: "workforce-1", IdentityUserID: "user-1", WorkStatus: identitymodel.IdentityWorkActive,
	}}
	repository.workforceAssignments = []identitymodel.IdentityWorkforceAssignment{{
		ID: "assignment-1", WorkforceProfileID: "workforce-1", OrganizationUnitID: "department",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
	}}
	repository.profileBindings = []identitymodel.IdentityProfileBinding{
		{IdentityUserID: "user-1", BindingKey: "member", Status: identitymodel.IdentityProfileBindingActive},
		{IdentityUserID: "member-only", BindingKey: "member", Status: identitymodel.IdentityProfileBindingActive},
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "general", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "employee", Audience: identitymodel.IdentityRoleAudienceWorkforce, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "elevated", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, RiskLevel: identitymodel.IdentityRoleRiskElevated},
		{Key: "service", Audience: identitymodel.IdentityRoleAudienceService, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
	})
	departmentActor := identitymodel.Principal{
		Known: true, UserID: "manager", DepartmentID: "department",
		Role: identitymodel.RoleSchema{RecordScope: "department", GrantableRoleKeys: []string{"elevated"}},
	}
	roles, err := service.ListAssignableRoles(t.Context(), "user-1", departmentActor)
	if err != nil || len(roles) != 4 {
		t.Fatalf("eligible roles=%+v err=%v", roles, err)
	}
	outsideActor := departmentActor
	outsideActor.DepartmentID = "other"
	if roles, err = service.ListAssignableRoles(t.Context(), "user-1", outsideActor); err != nil || len(roles) != 0 {
		t.Fatalf("out-of-scope roles=%+v err=%v", roles, err)
	}
	allRecordsActor := departmentActor
	allRecordsActor.Role = identitymodel.RoleSchema{RecordScope: "all_records"}
	if roles, err = service.ListAssignableRoles(t.Context(), "member-only", allRecordsActor); err != nil || len(roles) != 2 || roles[0].Key != "general" || roles[1].Key != "member" {
		t.Fatalf("member-only roles=%+v err=%v", roles, err)
	}
	if roles, err = service.ListAssignableWorkforceRoles(t.Context(), "workforce-1", allRecordsActor); err != nil || len(roles) != 2 || roles[0].Key != "employee" || roles[1].Key != "general" {
		t.Fatalf("workforce-context roles=%+v err=%v", roles, err)
	}
	if roles, err = service.ListAssignableWorkforceRoles(t.Context(), "missing", allRecordsActor); err != nil || len(roles) != 0 {
		t.Fatalf("missing workforce roles=%+v err=%v", roles, err)
	}
}

func TestIdentityUpsertUserWithRolesUsesOneGovernedAtomicMutation(t *testing.T) {
	repository, service := identityRolesFixture()
	actor := identitymodel.Principal{
		Known: true, UserID: "admin", Role: identitymodel.RoleSchema{
			RecordScope: "all_records",
		},
	}
	user := identitymodel.IdentityUser{ID: " user-1 ", Name: " Updated ", Email: " USER@EXAMPLE.COM ", Status: identitymodel.IdentityStatusActive}
	assignments := []identitymodel.IdentityUserRoleAssignment{{RoleID: "member-id", GrantReason: "support"}}
	if err := service.UpsertUserWithRoles(t.Context(), user, assignments, actor); err != nil {
		t.Fatal(err)
	}
	if repository.reconciledUser.ID != "user-1" || repository.reconciledUser.Name != "Updated" || repository.reconciledUser.Email != "user@example.com" ||
		len(repository.reconciledRoles) != 1 || repository.reconciledRoles[0].UserID != "user-1" ||
		repository.reconciledRoles[0].GrantedBy != "admin" || repository.reconciledRoles[0].Source != "manual" {
		t.Fatalf("atomic mutation user=%+v roles=%+v", repository.reconciledUser, repository.reconciledRoles)
	}
	repository.reconcileErr = errIdentityRolesRepository
	if err := service.UpsertUserWithRoles(t.Context(), user, assignments, actor); err != errIdentityRolesRepository {
		t.Fatalf("reconcile error=%v", err)
	}
}

func TestIdentityRoleAssignmentAndPrivilegeConditionEdges(t *testing.T) {
	empty := ""
	if !identityAssignmentActive(identitymodel.IdentityUserRoleAssignment{ExpiresAt: &empty}, time.Now()) {
		t.Fatal("empty expiry should remain active")
	}
	if identityPrivilegedAutoAssignableRole(identitymodel.IdentityRole{Key: "member"}) {
		t.Fatal("ordinary permission was treated as privileged")
	}
}

func TestIdentityAssignUserRole(t *testing.T) {
	repository, service := identityRolesFixture()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "member-id", ExpiresAt: &future}
	if err := service.AssignUserRole(t.Context(), assignment); err != nil || len(repository.assigned) != 1 {
		t.Fatalf("assignment failed: %v %#v", err, repository.assigned)
	}
	invalid := "invalid"
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "member-id", ExpiresAt: &invalid}); apperror.CodeOf(err) != "backend.identity.assignment_expires_at_invalid" {
		t.Fatalf("expected expires error, got %v", err)
	}
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "missing", RoleID: "member-id"}); apperror.CodeOf(err) != "backend.identity.user_not_found" {
		t.Fatalf("expected user error, got %v", err)
	}
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "missing"}); apperror.CodeOf(err) != "backend.identity.role_not_found" {
		t.Fatalf("expected role error, got %v", err)
	}
	repository.getUserErr = errIdentityRolesRepository
	if err := service.AssignUserRole(t.Context(), assignment); err != errIdentityRolesRepository {
		t.Fatalf("expected user repository error, got %v", err)
	}
	repository.getUserErr = nil
	repository.listRolesErr = errIdentityRolesRepository
	if err := service.AssignUserRole(t.Context(), assignment); err != errIdentityRolesRepository {
		t.Fatalf("expected role repository error, got %v", err)
	}
	repository.listRolesErr = nil
	repository.assignErr = errIdentityRolesRepository
	if err := service.AssignUserRole(t.Context(), assignment); err != errIdentityRolesRepository {
		t.Fatalf("expected assignment repository error, got %v", err)
	}
	repository.assignErr = nil
	assignments, err := service.ListUserRoleAssignments(t.Context(), "user-1")
	if err != nil || len(assignments) != len(repository.assignments) {
		t.Fatalf("assignments=%#v err=%v", assignments, err)
	}
}

func TestIdentityRoleByID(t *testing.T) {
	repository, service := identityRolesFixture()
	role, found, err := service.RoleByID(t.Context(), "viewer-id")
	if err != nil || !found || role.Key != "viewer" {
		t.Fatalf("role=%#v found=%v err=%v", role, found, err)
	}
	if role, found, err := service.roleByID(t.Context(), "member-id"); err != nil || !found || role.Key != "member" {
		t.Fatalf("private role lookup role=%#v found=%v err=%v", role, found, err)
	}
	if _, found, err := service.RoleByID(t.Context(), "missing"); err != nil || found {
		t.Fatalf("missing role found=%v err=%v", found, err)
	}
	repository.listRolesErr = errIdentityRolesRepository
	if _, _, err := service.RoleByID(t.Context(), "viewer-id"); err != errIdentityRolesRepository {
		t.Fatalf("expected role repository error, got %v", err)
	}
}

func TestIdentityRoleEligibilitySystemManagedAndConflicts(t *testing.T) {
	repository, service := identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged},
		{Key: "viewer", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentRequestOnly},
		{Key: "admin", Audience: identitymodel.IdentityRoleAudienceWorkforce, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, ConflictRoleKeys: []string{"security"}},
		{Key: "security", Audience: identitymodel.IdentityRoleAudienceWorkforce, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
	})
	service.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{active: true})
	member := identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "member-id", BindingKey: "member", ProfileID: "profile-1"}
	if err := service.AssignUserRole(t.Context(), member); apperror.CodeOf(err) != "backend.identity.system_managed_role_assignment_denied" {
		t.Fatalf("manual system role error=%v", err)
	}
	if err := service.AssignSystemManagedRole(t.Context(), member); err != nil || len(repository.assigned) != 1 || repository.assigned[0].Source != "profile_binding" {
		t.Fatalf("system assignment error=%v assigned=%#v", err, repository.assigned)
	}
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "viewer-id"}); apperror.CodeOf(err) != "backend.identity.role_request_required" {
		t.Fatalf("request-only error=%v", err)
	}
	repository.workforceProfiles = []identitymodel.IdentityWorkforceProfile{{ID: "workforce-1", OrganizationID: "org", IdentityUserID: "user-1", WorkerNo: "W-1", WorkStatus: identitymodel.IdentityWorkActive, PrimaryAssignmentID: "assignment-1"}}
	repository.workforceAssignments = []identitymodel.IdentityWorkforceAssignment{{ID: "assignment-1", WorkforceProfileID: "workforce-1", OrganizationUnitID: "department", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive}}
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "admin-id"}); apperror.CodeOf(err) != "backend.identity.workforce_role_eligibility_required" {
		t.Fatalf("missing workforce error=%v", err)
	}
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "permission-admin-id", WorkforceProfileID: "workforce-1", Status: "active"}}
	if err := service.AssignUserRole(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "admin-id", WorkforceProfileID: "workforce-1"}); apperror.CodeOf(err) != "backend.identity.role_conflict" {
		t.Fatalf("conflict error=%v", err)
	}
}

func TestIdentityManualBusinessRoleRequiresItsPublishedActiveBinding(t *testing.T) {
	repository, service := identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness,
		RequiredBindingKey: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
	}})
	base := identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "member-id"}
	for _, assignment := range []identitymodel.IdentityUserRoleAssignment{
		base,
		{UserID: base.UserID, RoleID: base.RoleID, BindingKey: "other", ProfileID: "profile-1"},
		{UserID: base.UserID, RoleID: base.RoleID, BindingKey: "member"},
	} {
		service.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{active: true})
		if err := service.AssignUserRole(t.Context(), assignment); apperror.CodeOf(err) != "backend.identity.business_role_eligibility_required" {
			t.Fatalf("invalid binding assignment=%#v error=%v", assignment, err)
		}
	}
	valid := identitymodel.IdentityUserRoleAssignment{UserID: base.UserID, RoleID: base.RoleID, BindingKey: "member", ProfileID: "profile-1"}
	service.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{active: false})
	if err := service.AssignUserRole(t.Context(), valid); apperror.CodeOf(err) != "backend.identity.business_role_eligibility_required" {
		t.Fatalf("inactive binding error=%v", err)
	}
	if len(repository.assigned) != 0 {
		t.Fatalf("invalid binding produced assignments: %#v", repository.assigned)
	}
	service.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{active: true})
	if err := service.AssignUserRole(t.Context(), valid); err != nil || len(repository.assigned) != 1 {
		t.Fatalf("active published binding assignment error=%v assignments=%#v", err, repository.assigned)
	}
}
