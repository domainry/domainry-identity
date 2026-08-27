package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityScopedSessionRevoker struct {
	workspaceID string
	userID      string
	count       int
	err         error
}

type identityScopedDeletionInspector struct {
	inspection IdentityUserDeletionInspection
	err        error
}

type identityScopedAccountRepository struct {
	*identityScopedRepository
	count        int
	disableErr   error
	setStatusErr error
}

func (r *identityScopedAccountRepository) DisableIdentityAccount(context.Context, string, string) (int, error) {
	return r.count, r.disableErr
}

func (r *identityScopedAccountRepository) SetIdentityUserStatus(context.Context, string, string, identitymodel.IdentityStatus) error {
	return r.setStatusErr
}

func (i *identityScopedDeletionInspector) InspectIdentityUserDeletion(context.Context, string, string) (IdentityUserDeletionInspection, error) {
	return i.inspection, i.err
}

func (r *identityScopedSessionRevoker) ForceLogoutUser(_ context.Context, workspaceID, userID string) (int, error) {
	r.workspaceID, r.userID = workspaceID, userID
	return r.count, r.err
}

func identityScopedCalls(service *IdentityApplicationService) []struct {
	name string
	call func(context.Context) error
} {
	return []struct {
		name string
		call func(context.Context) error
	}{
		{"list menus", func(ctx context.Context) error { _, err := service.ListMenus(ctx); return err }},
		{"effective menus", func(ctx context.Context) error { _, err := service.EffectiveMenus(ctx, "user"); return err }},
		{"resolve principal", func(ctx context.Context) error { _, err := service.ResolvePrincipal(ctx, "user"); return err }},
		{"resolve principal for role", func(ctx context.Context) error {
			_, err := service.ResolvePrincipalForRole(ctx, "user", "role")
			return err
		}},
		{"resolve permissions", func(ctx context.Context) error {
			_, err := service.ResolveEffectivePermissions(ctx, "user")
			return err
		}},
		{"resolve menus", func(ctx context.Context) error { _, err := service.ResolveEffectiveMenus(ctx, "user"); return err }},
		{"find user", func(ctx context.Context) error { _, _, err := service.FindUser(ctx, "user"); return err }},
		{"find department", func(ctx context.Context) error { _, _, err := service.FindDepartment(ctx, "department"); return err }},
		{"directory users", func(ctx context.Context) error { _, err := service.ListDirectoryUsers(ctx); return err }},
		{"directory workforce", func(ctx context.Context) error { _, err := service.ListDirectoryWorkforce(ctx); return err }},
		{"directory roles", func(ctx context.Context) error { _, err := service.ListDirectoryRoles(ctx); return err }},
		{"directory assignments", func(ctx context.Context) error {
			_, err := service.ListDirectoryUserRoleAssignments(ctx, "user")
			return err
		}},
		{"list departments", func(ctx context.Context) error { _, err := service.ListDepartments(ctx); return err }},
		{"upsert department", func(ctx context.Context) error {
			return service.UpsertDepartment(ctx, identitymodel.IdentityDepartment{})
		}},
		{"list users", func(ctx context.Context) error { _, err := service.ListUsers(ctx); return err }},
		{"search users", func(ctx context.Context) error {
			_, err := service.SearchUsers(ctx, identitymodel.IdentityListQuery{})
			return err
		}},
		{"user by id", func(ctx context.Context) error { _, _, err := service.UserByID(ctx, "user"); return err }},
		{"user by login", func(ctx context.Context) error { _, _, err := service.UserByLogin(ctx, "login"); return err }},
		{"upsert user", func(ctx context.Context) error { return service.UpsertUser(ctx, identitymodel.IdentityUser{}) }},
		{"remove user", func(ctx context.Context) error { return service.RemoveUser(ctx, "user") }},
		{"set user status", func(ctx context.Context) error {
			return service.SetUserStatus(ctx, "user", identitymodel.IdentityStatusActive)
		}},
		{"enable user", func(ctx context.Context) error { return service.EnableUser(ctx, " user ") }},
		{"list roles", func(ctx context.Context) error { _, err := service.ListRoles(ctx); return err }},
		{"search roles", func(ctx context.Context) error {
			_, err := service.SearchRoles(ctx, identitymodel.IdentityListQuery{})
			return err
		}},
		{"active roles", func(ctx context.Context) error { _, err := service.ActiveRolesForUser(ctx, "user"); return err }},
		{"assign user role", func(ctx context.Context) error {
			return service.AssignUserRole(ctx, identitymodel.IdentityUserRoleAssignment{})
		}},
		{"upsert user with roles", func(ctx context.Context) error {
			return service.UpsertUserWithRoles(ctx, identitymodel.IdentityUser{}, nil, identitymodel.Principal{})
		}},
		{"remove user role", func(ctx context.Context) error { return service.RemoveUserRole(ctx, "user", "role") }},
		{"remove user role governed", func(ctx context.Context) error {
			return service.RemoveUserRoleGoverned(ctx, "user", "role", "reason", identitymodel.Principal{})
		}},
		{"list user assignments", func(ctx context.Context) error { _, err := service.ListUserRoleAssignments(ctx, "user"); return err }},
		{"search user assignments", func(ctx context.Context) error {
			_, err := service.SearchUserRoleAssignments(ctx, "user", identitymodel.IdentityListQuery{})
			return err
		}},
		{"assignable roles", func(ctx context.Context) error {
			_, err := service.ListAssignableRoles(ctx, "user", identitymodel.Principal{Known: true, UserID: "actor", Role: identitymodel.RoleSchema{RecordScope: "all_records"}})
			return err
		}},
		{"assignable workforce roles", func(ctx context.Context) error {
			_, err := service.ListAssignableWorkforceRoles(ctx, "workforce", identitymodel.Principal{Known: true, UserID: "actor"})
			return err
		}},
		{"requestable roles", func(ctx context.Context) error { _, err := service.ListRequestableRoles(ctx); return err }},
		{"create role request", func(ctx context.Context) error {
			_, err := service.CreateRoleRequest(ctx, identitymodel.IdentityRoleRequest{})
			return err
		}},
		{"list role requests", func(ctx context.Context) error { _, err := service.ListRoleRequests(ctx, "", ""); return err }},
		{"approve role request", func(ctx context.Context) error {
			_, err := service.ApproveRoleRequest(ctx, "request", "reviewer", "note")
			return err
		}},
		{"reject role request", func(ctx context.Context) error {
			_, err := service.RejectRoleRequest(ctx, "request", "reviewer", "note")
			return err
		}},
		{"role by id", func(ctx context.Context) error { _, _, err := service.RoleByID(ctx, "role"); return err }},
		{"list role permissions", func(ctx context.Context) error {
			_, err := service.ListRolePermissionAssignments(ctx, "role")
			return err
		}},
		{"list role scopes", func(ctx context.Context) error { _, err := service.ListRoleDataScopes(ctx, "role"); return err }},
		{"list role fields", func(ctx context.Context) error { _, err := service.ListRoleFieldPermissions(ctx, "role"); return err }},
		{"upsert menu", func(ctx context.Context) error { return service.UpsertMenu(ctx, identitymodel.IdentityMenu{}) }},
		{"remove menu", func(ctx context.Context) error { _, err := service.RemoveMenu(ctx, "menu"); return err }},
		{"set role menus", func(ctx context.Context) error { return service.SetRoleMenus(ctx, "role", nil) }},
		{"list role menus", func(ctx context.Context) error { _, err := service.ListRoleMenuAssignments(ctx, "role"); return err }},
	}
}

func TestIdentityScopedMethodsRejectMissingWorkspace(t *testing.T) {
	service := NewIdentityApplicationService(&identityScopedRepository{}, nil)
	for _, test := range identityScopedCalls(service) {
		t.Run(test.name, func(t *testing.T) {
			if code := apperror.CodeOf(test.call(t.Context())); code != "backend.workspace_scope_required" {
				t.Fatalf("code=%q", code)
			}
		})
	}
}

func TestIdentityScopedMethodsDelegateWithinWorkspace(t *testing.T) {
	repository := &identityScopedRepository{}
	service := NewIdentityApplicationService(repository, nil)
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-a")
	for _, test := range identityScopedCalls(service) {
		t.Run(test.name, func(t *testing.T) {
			// Domain validation/not-found outcomes are allowed here; this test owns
			// only the Application wrapper's workspace scoping and delegation.
			if err := test.call(ctx); err != nil && apperror.CodeOf(err) == "backend.workspace_scope_required" {
				t.Fatalf("valid workspace was rejected: %v", err)
			}
		})
	}
}

func TestDisableUserOwnsAccountSecurityOrchestration(t *testing.T) {
	service := NewIdentityApplicationService(&identityScopedRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
	}, nil)
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-a")
	revoker := &identityScopedSessionRevoker{count: 3}

	count, err := service.DisableUser(ctx, " user-1 ", revoker)
	if err != nil || count != 3 || revoker.workspaceID != "workspace-a" || revoker.userID != "user-1" {
		t.Fatalf("count=%d workspace=%q user=%q err=%v", count, revoker.workspaceID, revoker.userID, err)
	}
}

func TestDisableUserRejectsMissingScopeOrSessionRevokerAndPropagatesFailure(t *testing.T) {
	service := NewIdentityApplicationService(&identityScopedRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
	}, nil)
	if _, err := service.DisableUser(t.Context(), "user-1", &identityScopedSessionRevoker{}); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("missing workspace code=%q", apperror.CodeOf(err))
	}
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-a")
	if _, err := service.DisableUser(ctx, "user-1", nil); apperror.CodeOf(err) != "backend.identity.user_security_unavailable" {
		t.Fatalf("missing revoker code=%q", apperror.CodeOf(err))
	}
	want := errors.New("session store unavailable")
	if _, err := service.DisableUser(ctx, "user-1", &identityScopedSessionRevoker{err: want}); !errors.Is(err, want) {
		t.Fatalf("revoker error=%v want=%v", err, want)
	}
}

func TestIdentityScopedImpactAndAccountDisableFailureEdges(t *testing.T) {
	base := &identityScopedRepository{users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}}}
	service := NewIdentityApplicationServiceWithDependencies(base, nil, IdentityApplicationServiceDependencies{
		UserDeletionInspector: &identityScopedDeletionInspector{},
	})
	if _, err := service.UserDeletionImpact(t.Context(), "user-1"); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("deletion impact missing scope=%v", err)
	}
	if _, err := service.UserDisableImpact(t.Context(), "user-1"); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("disable impact missing scope=%v", err)
	}
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace")
	impactFailure := errors.New("impact")
	impactRepository := &identityScopedStatusFaultRepository{identityScopedRepository: base, listUsersErr: impactFailure}
	impactService := NewIdentityApplicationService(impactRepository, nil)
	if _, err := impactService.UserDisableImpact(ctx, "user-1"); !errors.Is(err, impactFailure) {
		t.Fatalf("disable impact domain error=%v", err)
	}

	account := &identityScopedAccountRepository{identityScopedRepository: base, count: 4}
	accountService := NewIdentityApplicationService(account, nil)
	if count, err := accountService.DisableUser(ctx, "user-1", nil); err != nil || count != 4 {
		t.Fatalf("atomic disable count=%d err=%v", count, err)
	}
	account.disableErr = errors.New("disable")
	if _, err := accountService.DisableUser(ctx, "user-1", nil); !errors.Is(err, account.disableErr) {
		t.Fatalf("atomic disable error=%v", err)
	}

	setStatus := &identityScopedAccountRepository{identityScopedRepository: base, setStatusErr: errors.New("status")}
	// Hide the atomic account-disable capability so the fallback orchestration
	// reaches the status update. A dedicated wrapper below exposes only the base
	// repository contract with the failing status method.
	fallback := &identityScopedStatusFaultRepository{identityScopedRepository: setStatus.identityScopedRepository, err: setStatus.setStatusErr}
	fallbackService := NewIdentityApplicationService(fallback, nil)
	if _, err := fallbackService.DisableUser(ctx, "user-1", &identityScopedSessionRevoker{}); !errors.Is(err, setStatus.setStatusErr) {
		t.Fatalf("fallback status error=%v", err)
	}
}

type identityScopedStatusFaultRepository struct {
	*identityScopedRepository
	err          error
	listUsersErr error
}

func (r *identityScopedStatusFaultRepository) SetIdentityUserStatus(context.Context, string, string, identitymodel.IdentityStatus) error {
	return r.err
}

func (r *identityScopedStatusFaultRepository) ListIdentityUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	if r.listUsersErr != nil {
		return nil, r.listUsersErr
	}
	return r.identityScopedRepository.ListIdentityUsers(ctx, workspaceID)
}

func TestUserDeletionImpactAggregatesEveryCrossDomainBlocker(t *testing.T) {
	service := NewIdentityApplicationServiceWithDependencies(&identityScopedRepository{
		users:       []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "role-1", Status: "active"}},
	}, nil, IdentityApplicationServiceDependencies{
		UserDeletionInspector: &identityScopedDeletionInspector{inspection: IdentityUserDeletionInspection{
			BusinessProfileReferences: []identitymodel.IdentityUserRecordReference{{ObjectKey: "member", FieldKey: "identity_user", Count: 1}},
			OwnedRecordReferences:     []identitymodel.IdentityUserRecordReference{{ObjectKey: "order", FieldKey: "owner", Count: 2}},
			PendingApprovalTaskIDs:    []string{"task-1"},
			RetainedAuditEventIDs:     []string{"audit-1"},
			ActiveLegalHoldIDs:        []string{"hold-1"},
		}},
	})
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-a")
	impact, err := service.UserDeletionImpact(ctx, "user-1")
	wantBlockers := []string{"approval_task", "audit_retention", "business_profile", "legal_hold", "record_ownership"}
	if err != nil || impact.CanDelete || !reflect.DeepEqual(impact.Blockers, wantBlockers) {
		t.Fatalf("impact=%+v err=%v", impact, err)
	}
	if err := service.RemoveUser(ctx, "user-1"); apperror.CodeOf(err) != "backend.identity.user_deletion_blocked" {
		t.Fatalf("delete blocker code=%q err=%v", apperror.CodeOf(err), err)
	}
}

func TestUserDisableImpactIncludesEveryIdentityAndEntitlementProjection(t *testing.T) {
	service := NewIdentityApplicationService(&identityScopedRepository{
		users:       []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "member", Status: "active"}},
	}, nil)
	impact, err := service.UserDisableImpact(requestcontext.WithWorkspaceID(t.Context(), "workspace-a"), "user-1")
	if err != nil || len(impact.ProfileBindings) != 0 || len(impact.ActiveEntitlementRoleIDs) != 1 || !impact.SessionsWillBeRevoked || !impact.BusinessFactsPreserved {
		t.Fatalf("disable impact=%+v err=%v", impact, err)
	}
}

func TestUserDeletionInspectionUsesIdentityLocalDefaultAndPropagatesInjectedFailure(t *testing.T) {
	repository := &identityScopedRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
	}
	service := NewIdentityApplicationService(repository, nil)
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-a")
	if impact, err := service.UserDeletionImpact(ctx, "user-1"); err != nil || !impact.CanDelete || len(impact.Blockers) != 0 {
		t.Fatalf("Identity-local impact=%+v err=%v", impact, err)
	}
	failure := errors.New("inspection failed")
	service = NewIdentityApplicationServiceWithDependencies(repository, nil, IdentityApplicationServiceDependencies{
		UserDeletionInspector: &identityScopedDeletionInspector{err: failure},
	})
	if _, err := service.UserDeletionImpact(ctx, "user-1"); !errors.Is(err, failure) {
		t.Fatalf("inspection error=%v", err)
	}
	service = NewIdentityApplicationServiceWithDependencies(repository, nil, IdentityApplicationServiceDependencies{
		UserDeletionInspector: &identityScopedDeletionInspector{},
	})
	if impact, err := service.UserDeletionImpact(ctx, "user-1"); err != nil || !impact.CanDelete || len(impact.Blockers) != 0 {
		t.Fatalf("clear impact=%+v err=%v", impact, err)
	}
	if err := service.RemoveUser(ctx, "user-1"); err != nil {
		t.Fatalf("clear deletion failed: %v", err)
	}
}
