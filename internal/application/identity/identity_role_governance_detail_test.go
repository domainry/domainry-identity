package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type roleGovernanceFaultRepository struct {
	*identityScopedRepository
	roleCalls     int
	failRoleCall  int
	failRoleMenus bool
	failMenus     bool
	failUserRoles bool
}

var errRoleGovernanceProjection = errors.New("role governance projection failed")

func (r *roleGovernanceFaultRepository) ListIdentityRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	r.roleCalls++
	if r.roleCalls == r.failRoleCall {
		return nil, errRoleGovernanceProjection
	}
	return r.identityScopedRepository.ListIdentityRoles(ctx, workspaceID)
}

func (r *roleGovernanceFaultRepository) ListIdentityRoleMenuAssignments(ctx context.Context, workspaceID, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	if r.failRoleMenus {
		return nil, errRoleGovernanceProjection
	}
	return r.identityScopedRepository.ListIdentityRoleMenuAssignments(ctx, workspaceID, roleID)
}

func (r *roleGovernanceFaultRepository) ListIdentityMenus(ctx context.Context, workspaceID string) ([]identitymodel.IdentityMenu, error) {
	if r.failMenus {
		return nil, errRoleGovernanceProjection
	}
	return r.identityScopedRepository.ListIdentityMenus(ctx, workspaceID)
}

func (r *roleGovernanceFaultRepository) ListIdentityUserRoleAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	if r.failUserRoles {
		return nil, errRoleGovernanceProjection
	}
	return r.identityScopedRepository.ListIdentityUserRoleAssignments(ctx, workspaceID, userID)
}

func TestRoleGovernanceDetailComposesPublishedAuthorities(t *testing.T) {
	repository := &identityScopedRepository{
		roles: []identitymodel.IdentityRole{{ID: "role-1", Key: "sales", Label: "Sales", Status: identitymodel.IdentityStatusActive}},
		menus: []identitymodel.IdentityMenu{
			{ID: "menu-orders", Key: "orders", Label: "Orders"},
			{ID: "menu-reports-id", Key: "reports", Label: "Reports"},
			{ID: "menu-other", Key: "other", Label: "Other"},
		},
		roleMenus: []identitymodel.IdentityRoleMenuAssignment{{RoleID: "role-1", MenuID: "menu-orders"}, {RoleID: "role-1", MenuID: "reports"}},
		assignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "user-1", RoleID: "role-1", Source: "manual"},
			{UserID: "user-2", RoleID: "sales", BindingKey: "member"},
			{UserID: "user-3", RoleID: "other"},
		},
	}
	service := NewIdentityApplicationService(repository, nil)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "sales", Permissions: []string{"order.read"}, RecordScope: "all_records",
		Audience: identitymodel.IdentityRoleAudienceUser, AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
		PermissionSetKeys: []string{"direct"}, PermissionSetGroups: []string{"sales-group"}, GuardrailKeys: []string{"deny-export"},
		DataPermissions:  []identitymodel.DataPermission{{ObjectKey: "order", Scope: "organization"}},
		FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "order", FieldKey: "amount", Read: true, Export: false}},
		ExportRules:      []identitymodel.ExportRule{{ObjectKey: "order", Mode: "allowlist", Fields: []string{"id"}}},
	}})
	service.ReplaceAuthorizationPolicies(
		[]identitymodel.IdentityPermissionSet{
			{Key: "direct", Name: "Direct"},
			{Key: "grouped", Name: "Grouped"},
			{Key: "unused", Name: "Unused"},
		},
		[]identitymodel.IdentityPermissionSetGroup{
			{Key: "sales-group", Name: "Sales group", PermissionSetKeys: []string{"grouped"}},
			{Key: "unused", Name: "Unused"},
		},
		[]identitymodel.IdentityGuardrailPolicy{
			{Key: "deny-export", Name: "No export"},
			{Key: "unused", Name: "Unused"},
		},
	)

	ctx := requestcontext.WithWorkspaceID(context.Background(), "workspace-1")
	detail, err := service.RoleGovernanceDetail(ctx, " role-1 ")
	if err != nil {
		t.Fatalf("detail error = %v", err)
	}
	if detail.Role.Key != "sales" || detail.Definition.Audience != identitymodel.IdentityRoleAudienceUser {
		t.Fatalf("role projection = %#v / %#v", detail.Role, detail.Definition)
	}
	if len(detail.PermissionSets) != 2 || detail.PermissionSets[0].Key != "direct" || detail.PermissionSets[1].Key != "grouped" {
		t.Fatalf("permission sets = %#v", detail.PermissionSets)
	}
	if len(detail.PermissionSetGroups) != 1 || len(detail.Guardrails) != 1 {
		t.Fatalf("groups/guardrails = %#v / %#v", detail.PermissionSetGroups, detail.Guardrails)
	}
	if len(detail.Permissions) != 1 || len(detail.DataScopes) != 1 || len(detail.FieldPermissions) != 1 || len(detail.ExportRules) != 1 {
		t.Fatalf("authorization projection = %#v", detail)
	}
	if len(detail.Menus) != 2 || detail.Menus[0].ID != "menu-orders" || len(detail.Members) != 2 {
		t.Fatalf("menus/members = %#v / %#v", detail.Menus, detail.Members)
	}
}

func TestRoleGovernanceDetailRejectsUnknownRoleAndMissingWorkspace(t *testing.T) {
	service := NewIdentityApplicationService(&identityScopedRepository{}, nil)
	_, err := service.RoleGovernanceDetail(requestcontext.WithWorkspaceID(context.Background(), "workspace-1"), "missing")
	if apperror.CodeOf(err) != "backend.identity.role_not_found" {
		t.Fatalf("unknown role error = %v", err)
	}
	if _, err = service.RoleGovernanceDetail(context.Background(), "missing"); err == nil {
		t.Fatal("missing workspace should fail")
	}
}

func TestRoleGovernanceDetailPropagatesProjectionFailures(t *testing.T) {
	tests := []struct {
		name          string
		failRoleCall  int
		failRoleMenus bool
		failMenus     bool
		failUserRoles bool
	}{
		{name: "role lookup", failRoleCall: 1},
		{name: "permissions", failRoleCall: 2},
		{name: "data scopes", failRoleCall: 3},
		{name: "field permissions", failRoleCall: 4},
		{name: "role menus", failRoleMenus: true},
		{name: "menus", failMenus: true},
		{name: "members", failUserRoles: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &roleGovernanceFaultRepository{
				identityScopedRepository: &identityScopedRepository{roles: []identitymodel.IdentityRole{{ID: "role-1", Key: "sales"}}},
				failRoleCall:             test.failRoleCall, failRoleMenus: test.failRoleMenus, failMenus: test.failMenus, failUserRoles: test.failUserRoles,
			}
			service := NewIdentityApplicationService(repository, nil)
			service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "sales"}})
			_, err := service.RoleGovernanceDetail(requestcontext.WithWorkspaceID(context.Background(), "workspace-1"), "role-1")
			if !errors.Is(err, errRoleGovernanceProjection) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestRoleGovernanceDetailFiltersIgnoreBlankAndUnknownKeys(t *testing.T) {
	keys := stringSet([]string{"", " wanted ", "wanted"})
	if len(keys) != 1 || !keys["wanted"] {
		t.Fatalf("key set = %#v", keys)
	}
	if got := filterPermissionSets([]identitymodel.IdentityPermissionSet{{Key: "wanted"}, {Key: "other"}}, keys); len(got) != 1 || got[0].Key != "wanted" {
		t.Fatalf("permission sets = %#v", got)
	}
	if got := filterPermissionSetGroups([]identitymodel.IdentityPermissionSetGroup{{Key: "wanted"}, {Key: "other"}}, keys); len(got) != 1 || got[0].Key != "wanted" {
		t.Fatalf("groups = %#v", got)
	}
	if got := filterGuardrails([]identitymodel.IdentityGuardrailPolicy{{Key: "wanted"}, {Key: "other"}}, keys); len(got) != 1 || got[0].Key != "wanted" {
		t.Fatalf("guardrails = %#v", got)
	}
}
