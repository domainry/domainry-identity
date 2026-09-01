package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type workforcePositionResolverProbe struct {
	positions []identitymodel.IdentityWorkforcePosition
	err       error
}

func (p workforcePositionResolverProbe) ListWorkforcePositions(context.Context, string) ([]identitymodel.IdentityWorkforcePosition, error) {
	return p.positions, p.err
}

func workforceProjectionFixture() (*IdentityApplicationService, *directoryProjectionRepository, identitymodel.Principal, context.Context) {
	expired := "2000-01-01T00:00:00Z"
	repository := &directoryProjectionRepository{
		identityScopedRepository: &identityScopedRepository{
			departments: []identitymodel.IdentityDepartment{
				{ID: "sales", Name: "Sales", Path: "/company/sales"},
				{ID: "sales-east", Name: "Sales East", Path: "/company/sales/east"},
			},
			users: []identitymodel.IdentityUser{
				{ID: "user-a", Name: "Alice", Email: "alice@example.com", Phone: "100", UpdatedAt: "now"},
				{ID: "manager", Name: "Manager"},
			},
			roles: []identitymodel.IdentityRole{
				{ID: "role-sales-manager", Key: "sales_manager", Label: "Sales Manager", Status: identitymodel.IdentityStatusActive},
				{ID: "role-expired", Key: "expired_role", Label: "Expired Role", Status: identitymodel.IdentityStatusActive},
				{ID: "role-future", Key: "future_role", Label: "Future Role", Status: identitymodel.IdentityStatusActive},
				{ID: "role-revoked", Key: "revoked_role", Label: "Revoked Role", Status: identitymodel.IdentityStatusActive},
				{ID: "role-disabled", Key: "disabled_role", Label: "Disabled Role", Status: identitymodel.IdentityStatusDisabled},
				{ID: "role-unpublished", Key: "unpublished_role", Label: "Unpublished Role", Status: identitymodel.IdentityStatusActive},
			},
			assignments: []identitymodel.IdentityUserRoleAssignment{
				{UserID: "user-a", RoleID: "role-sales-manager", WorkforceProfileID: "profile-a", Status: "active"},
				{UserID: "user-a", RoleID: "role-expired", WorkforceProfileID: "profile-a", Status: "active", ExpiresAt: &expired},
				{UserID: "user-a", RoleID: "role-future", WorkforceProfileID: "profile-a", Status: "active", ValidFrom: "2999-01-01T00:00:00Z"},
				{UserID: "user-a", RoleID: "role-revoked", WorkforceProfileID: "profile-a", Status: "revoked"},
				{UserID: "user-a", RoleID: "role-disabled", WorkforceProfileID: "profile-a", Status: "active"},
				{UserID: "user-a", RoleID: "role-unpublished", WorkforceProfileID: "profile-a", Status: "active"},
				{UserID: "other-user", RoleID: "role-sales-manager", Status: "active"},
			},
		},
		workforce: []identitymodel.IdentityWorkforceProfile{
			{ID: "profile-a", IdentityUserID: "user-a", WorkerNo: "E-002", WorkStatus: identitymodel.IdentityWorkActive, PrimaryAssignmentID: "assignment-a"},
			{ID: "profile-manager", IdentityUserID: "manager", WorkerNo: "E-001", WorkStatus: identitymodel.IdentityWorkActive},
			{ID: "profile-unassigned", IdentityUserID: "missing", WorkerNo: "E-002", WorkStatus: identitymodel.IdentityWorkPending},
			{ID: "profile-ghost-manager", IdentityUserID: "ghost", WorkerNo: "E-004", WorkStatus: identitymodel.IdentityWorkActive},
		},
		workforceAssignments: []identitymodel.IdentityWorkforceAssignment{
			{ID: "assignment-a", WorkforceProfileID: "profile-a", OrganizationUnitID: "sales", PositionID: "position-manager", ManagerWorkforceProfileID: "profile-manager", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
			{ID: "assignment-manager", WorkforceProfileID: "profile-manager", OrganizationUnitID: "sales-east", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
			{ID: "assignment-unassigned", WorkforceProfileID: "profile-unassigned", OrganizationUnitID: "missing-department", ManagerWorkforceProfileID: "profile-ghost-manager", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive},
		},
	}
	service := NewIdentityApplicationServiceWithDependencies(repository, nil, IdentityApplicationServiceDependencies{
		PositionResolver: workforcePositionResolverProbe{positions: []identitymodel.IdentityWorkforcePosition{{ID: "position-manager", Code: "MGR", Name: "Manager"}}},
	})
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "sales_manager", Permissions: []string{"sales.approve"}},
		{Key: "expired_role", Permissions: []string{"expired.permission"}},
		{Key: "future_role", Permissions: []string{"future.permission"}},
		{Key: "revoked_role", Permissions: []string{"revoked.permission"}},
		{Key: "disabled_role", Permissions: []string{"disabled.permission"}},
	})
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", UserID: "admin", Role: identitymodel.RoleSchema{RecordScope: "all_records"}}
	return service, repository, principal, requestcontext.WithWorkspaceID(context.Background(), "workspace-primary")
}

func TestWorkforceApplicationProjectionComposesAndPagesFacts(t *testing.T) {
	service, _, principal, ctx := workforceProjectionFixture()
	page, err := service.ListWorkforceApplicationProjection(ctx, principal)
	if err != nil || page.Total != 4 || page.PageSize != 4 || page.HasNext {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if page.Items[0].Profile.ID != "profile-manager" || page.Items[1].DisplayName != "Alice" || page.Items[1].Department.ID != "sales" ||
		page.Items[1].Position.Code != "MGR" || page.Items[1].Manager.DisplayName != "Manager" || page.Items[2].Manager.DisplayName != "" ||
		len(page.Items[1].Roles) != 1 || page.Items[1].Roles[0] != (identitymodel.IdentityWorkforceRole{ID: "role-sales-manager", Key: "sales_manager", Label: "Sales Manager"}) ||
		page.Items[0].Roles == nil || len(page.Items[0].Roles) != 0 {
		t.Fatalf("items=%+v", page.Items)
	}
	filtered, err := service.ListWorkforceApplicationProjection(ctx, principal, identitymodel.IdentityWorkforceProjectionQuery{
		AfterID: "profile-a", PageSize: 1, Search: "sales", DepartmentID: "sales", WorkStatus: identitymodel.IdentityWorkActive,
	})
	if err != nil || filtered.Total != 1 || len(filtered.Items) != 0 || filtered.PageSize != 1 {
		t.Fatalf("filtered=%+v err=%v", filtered, err)
	}
	if empty, err := service.ListWorkforceApplicationProjection(ctx, principal, identitymodel.IdentityWorkforceProjectionQuery{PageSize: 1, Search: "not-present"}); err != nil || empty.Total != 0 || empty.PageSize != 1 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
	if oversized, err := service.ListWorkforceApplicationProjection(ctx, principal, identitymodel.IdentityWorkforceProjectionQuery{PageSize: 100}); err != nil || oversized.PageSize != 4 {
		t.Fatalf("oversized=%+v err=%v", oversized, err)
	}
	service.positionResolver = nil
	if _, err := service.ListWorkforceApplicationProjection(ctx, principal); err != nil {
		t.Fatalf("projection without position resolver: %v", err)
	}
	principal.Role = identitymodel.RoleSchema{RecordScope: "owned_records"}
	principal.UserID = "nobody"
	if denied, err := service.ListWorkforceApplicationProjection(ctx, principal); err != nil || denied.Total != 0 {
		t.Fatalf("denied=%+v err=%v", denied, err)
	}
}

func TestWorkforceProjectionFailureBoundaries(t *testing.T) {
	service, repository, principal, ctx := workforceProjectionFixture()
	if _, err := service.ListWorkforceApplicationProjection(ctx, identitymodel.Principal{}); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("authorization err=%v", err)
	}
	if _, err := service.ListWorkforceApplicationProjection(context.Background(), principal); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("context scope err=%v", err)
	}
	if _, err := NewIdentityApplicationService(&identityScopedRepository{}, nil).ListWorkforceApplicationProjection(ctx, principal); apperror.CodeOf(err) != "backend.identity.workforce_unavailable" {
		t.Fatalf("capability err=%v", err)
	}
	for _, stage := range []string{"workforce", "workforce_assignments", "users", "departments", "assignments", "roles"} {
		repository.fail, repository.err = stage, errors.New(stage)
		if _, err := service.ListWorkforceApplicationProjection(ctx, principal); !errors.Is(err, repository.err) {
			t.Fatalf("%s err=%v", stage, err)
		}
	}
	repository.fail = ""
	resolverErr := errors.New("positions")
	service.positionResolver = workforcePositionResolverProbe{err: resolverErr}
	if _, err := service.ListWorkforceApplicationProjection(ctx, principal); !errors.Is(err, resolverErr) {
		t.Fatalf("position err=%v", err)
	}
}

func TestListWorkforceProfilesForPrincipalBoundaries(t *testing.T) {
	service, repository, principal, ctx := workforceProjectionFixture()
	if _, err := service.ListWorkforceProfilesForPrincipal(ctx, identitymodel.Principal{}); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("authorization err=%v", err)
	}
	if _, err := service.ListWorkforceProfilesForPrincipal(context.Background(), principal); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("context scope err=%v", err)
	}
	for _, stage := range []string{"workforce", "workforce_assignments", "departments"} {
		repository.fail, repository.err = stage, errors.New(stage)
		if _, err := service.ListWorkforceProfilesForPrincipal(ctx, principal); !errors.Is(err, repository.err) {
			t.Fatalf("%s err=%v", stage, err)
		}
	}
	repository.fail = ""
	principal.Role = identitymodel.RoleSchema{RecordScope: "owned_records"}
	principal.UserID = "user-a"
	profiles, err := service.ListWorkforceProfilesForPrincipal(ctx, principal)
	if err != nil || len(profiles) != 1 || profiles[0].ID != "profile-a" {
		t.Fatalf("profiles=%+v err=%v", profiles, err)
	}
}

func TestWorkforceScopeAndFilterRemainingCombinations(t *testing.T) {
	profile := identitymodel.IdentityWorkforceProfile{IdentityUserID: "employee"}
	primary := identitymodel.IdentityWorkforceAssignment{ID: "fallback", OrganizationUnitID: "sales", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive}
	if assignment, ok := workforcePrimaryAssignment(profile, []identitymodel.IdentityWorkforceAssignment{{AssignmentType: identitymodel.IdentityWorkforceAssignmentSecondary}, primary}); !ok || assignment.ID != "fallback" {
		t.Fatalf("fallback=%+v ok=%v", assignment, ok)
	}
	if _, ok := workforcePrimaryAssignment(profile, nil); ok {
		t.Fatal("missing assignment accepted")
	}
	departments := map[string]identitymodel.IdentityDepartment{"sales": {ID: "sales", Path: "/company/sales"}}
	for _, test := range []struct {
		principal identitymodel.Principal
		allowed   bool
	}{
		{principal: identitymodel.Principal{UserID: "employee", Role: identitymodel.RoleSchema{RecordScope: "team"}}, allowed: true},
		{principal: identitymodel.Principal{UserID: "manager", DepartmentID: "sales", Role: identitymodel.RoleSchema{RecordScope: "department"}}, allowed: true},
		{principal: identitymodel.Principal{UserID: "manager", DepartmentID: "other", DepartmentPath: "/company/sales", Role: identitymodel.RoleSchema{RecordScope: "department"}}, allowed: true},
		{principal: identitymodel.Principal{UserID: "manager", DepartmentPath: "/company/sales", Role: identitymodel.RoleSchema{RecordScope: "department"}}, allowed: true},
		{principal: identitymodel.Principal{UserID: "manager", DepartmentPath: "", Role: identitymodel.RoleSchema{RecordScope: "department"}}},
		{principal: identitymodel.Principal{UserID: "manager", DepartmentPath: "/company/sales", Role: identitymodel.RoleSchema{RecordScope: "all_records"}}, allowed: true},
	} {
		if got := identityWorkforceReadScopeAllows(test.principal, profile, []identitymodel.IdentityWorkforceAssignment{primary}, departments); got != test.allowed {
			t.Fatalf("principal=%+v got=%v want=%v", test.principal, got, test.allowed)
		}
	}
	if identityWorkforceReadScopeAllows(identitymodel.Principal{UserID: "manager", DepartmentPath: "/company/sales", Role: identitymodel.RoleSchema{RecordScope: "department"}}, profile, []identitymodel.IdentityWorkforceAssignment{primary}, nil) {
		t.Fatal("missing department allowed")
	}
	if identityWorkforceReadScopeAllows(identitymodel.Principal{UserID: "manager", DepartmentPath: "/company/sales", Role: identitymodel.RoleSchema{RecordScope: "department"}}, profile, nil, departments) {
		t.Fatal("missing assignment allowed")
	}
	profile.PrimaryAssignmentID = "preferred"
	if assignment, ok := workforcePrimaryAssignment(profile, []identitymodel.IdentityWorkforceAssignment{{ID: "other", AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusDisabled}, primary}); !ok || assignment.ID != "fallback" {
		t.Fatalf("preferred fallback=%+v ok=%v", assignment, ok)
	}
	items := []identitymodel.IdentityWorkforceProjectionItem{
		{Profile: identitymodel.IdentityWorkforceProfile{ID: "a", WorkStatus: identitymodel.IdentityWorkActive}, DisplayName: "Alice", Email: "alice@example.com"},
		{Profile: identitymodel.IdentityWorkforceProfile{ID: "b", WorkStatus: identitymodel.IdentityWorkSuspended}, Phone: "200", Department: &identitymodel.IdentityDepartment{ID: "sales", Name: "Sales"}},
	}
	for _, query := range []identitymodel.IdentityWorkforceProjectionQuery{
		{DepartmentID: "sales"}, {WorkStatus: identitymodel.IdentityWorkActive}, {Search: "alice"}, {Search: "missing"},
	} {
		_ = filterWorkforceApplicationProjection(items, query)
	}
}
