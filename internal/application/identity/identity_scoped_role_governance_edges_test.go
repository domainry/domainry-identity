package identity

import (
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestAssignUserRoleGovernedCoversRiskAndGrantCeilingPolicies(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace")
	base := &identityScopedRepository{
		users: []identitymodel.IdentityUser{{ID: "target", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{
			{ID: "normal", Key: "normal", Status: identitymodel.IdentityStatusActive},
			{ID: "blank-risk", Key: "blank-risk", Status: identitymodel.IdentityStatusActive},
			{ID: "elevated", Key: "elevated", Status: identitymodel.IdentityStatusActive},
			{ID: "privileged", Key: "privileged", Status: identitymodel.IdentityStatusActive},
			{ID: "unpublished", Key: "unpublished", Status: identitymodel.IdentityStatusActive},
		},
	}
	repository := &effectiveAccessFaultRepository{identityScopedRepository: base}
	service := NewIdentityApplicationService(repository, nil)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "normal", RiskLevel: identitymodel.IdentityRoleRiskNormal, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "blank-risk", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "elevated", RiskLevel: identitymodel.IdentityRoleRiskElevated, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "privileged", RiskLevel: identitymodel.IdentityRoleRiskPrivileged, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
	})
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: "target", RoleID: "normal", Status: "active"}
	actor := identitymodel.Principal{Known: true, UserID: "actor", WorkspaceID: "workspace"}

	if err := service.AssignUserRoleGoverned(t.Context(), assignment, actor); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("missing scope=%v", err)
	}
	unknown := actor
	unknown.Known = false
	if err := service.AssignUserRoleGoverned(ctx, assignment, unknown); apperror.CodeOf(err) != "backend.identity.entitlement_actor_required" {
		t.Fatalf("unknown actor=%v", err)
	}
	blankActor := actor
	blankActor.UserID = " "
	if err := service.AssignUserRoleGoverned(ctx, assignment, blankActor); apperror.CodeOf(err) != "backend.identity.entitlement_actor_required" {
		t.Fatalf("blank actor=%v", err)
	}
	repository.fail, repository.err = "roles", errors.New("roles")
	if err := service.AssignUserRoleGoverned(ctx, assignment, actor); !errors.Is(err, repository.err) {
		t.Fatalf("role load error=%v", err)
	}
	repository.fail = ""
	missing := assignment
	missing.RoleID = "missing"
	if err := service.AssignUserRoleGoverned(ctx, missing, actor); apperror.CodeOf(err) != "backend.identity.role_not_found" {
		t.Fatalf("missing role=%v", err)
	}
	unpublished := assignment
	unpublished.RoleID = "unpublished"
	if err := service.AssignUserRoleGoverned(ctx, unpublished, actor); err != nil {
		t.Fatalf("unpublished role should use directory policy: %v", err)
	}
	blankRisk := assignment
	blankRisk.RoleID = "blank-risk"
	if err := service.AssignUserRoleGoverned(ctx, blankRisk, actor); err != nil {
		t.Fatalf("blank risk default=%v", err)
	}
	privileged := assignment
	privileged.RoleID, privileged.UserID = "privileged", "actor"
	if err := service.AssignUserRoleGoverned(ctx, privileged, actor); apperror.CodeOf(err) != "backend.identity.privileged_self_grant_denied" {
		t.Fatalf("self grant=%v", err)
	}
	privileged.UserID = "target"
	privilegedGranter := actor
	privilegedGranter.Role.GrantableRoleKeys = []string{"*"}
	if err := service.AssignUserRoleGoverned(ctx, privileged, privilegedGranter); err != nil {
		t.Fatalf("privileged non-self grant=%v", err)
	}
	elevated := assignment
	elevated.RoleID = "elevated"
	if err := service.AssignUserRoleGoverned(ctx, elevated, actor); apperror.CodeOf(err) != "backend.identity.role_grant_ceiling_exceeded" {
		t.Fatalf("grant ceiling=%v", err)
	}
	for _, grantable := range [][]string{{"*"}, {"other", " elevated "}} {
		granter := actor
		granter.Role.GrantableRoleKeys = grantable
		if err := service.AssignUserRoleGoverned(ctx, elevated, granter); err != nil {
			t.Fatalf("grantable=%v err=%v", grantable, err)
		}
	}
}

func TestValidateRoleMenusCoversRoleMenuAndRoutePolicies(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace")
	base := &identityScopedRepository{
		roles: []identitymodel.IdentityRole{
			{ID: "role", Key: "role", Status: identitymodel.IdentityStatusActive},
			{ID: "unpublished", Key: "unpublished", Status: identitymodel.IdentityStatusActive},
		},
		menus: []identitymodel.IdentityMenu{
			{ID: "header", Key: "header", Status: identitymodel.IdentityStatusActive},
			{ID: "account", Key: "account", Route: "/admin/security/accounts", Status: identitymodel.IdentityStatusActive},
			{ID: "unknown-route", Key: "unknown-route", Route: "/admin/not-registered", Status: identitymodel.IdentityStatusActive},
			{ID: "business-members", Key: "business-members", Route: "business.members", Status: identitymodel.IdentityStatusActive},
			{ID: "literal-business-path", Key: "literal-business-path", Route: "/business/members", Status: identitymodel.IdentityStatusActive},
			{ID: "disabled", Key: "disabled", Status: identitymodel.IdentityStatusDisabled},
			{ID: "deleted", Key: "deleted", Status: identitymodel.IdentityStatusDeleted},
		},
	}
	repository := &effectiveAccessFaultRepository{identityScopedRepository: base}
	service := NewIdentityApplicationService(repository, nil)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "role", Permissions: []string{"identity.users.read"}}})

	if err := service.ValidateRoleMenus(t.Context(), "role", nil); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("missing scope=%v", err)
	}
	repository.fail, repository.err = "roles", errors.New("roles")
	if err := service.ValidateRoleMenus(ctx, "role", nil); !errors.Is(err, repository.err) {
		t.Fatalf("role load error=%v", err)
	}
	repository.fail = ""
	if err := service.ValidateRoleMenus(ctx, "missing", nil); apperror.CodeOf(err) != "backend.identity.role_not_found" {
		t.Fatalf("missing role=%v", err)
	}
	if err := service.ValidateRoleMenus(ctx, "unpublished", nil); apperror.CodeOf(err) != "backend.identity.role_definition_not_published" {
		t.Fatalf("unpublished role=%v", err)
	}
	repository.fail, repository.err = "menus", errors.New("menus")
	if err := service.ValidateRoleMenus(ctx, "role", nil); !errors.Is(err, repository.err) {
		t.Fatalf("menu load error=%v", err)
	}
	repository.fail = ""
	if err := service.ValidateRoleMenus(ctx, "role", []string{" ", "header"}); err != nil {
		t.Fatalf("header menu=%v", err)
	}
	if err := service.ValidateRoleMenus(ctx, "role", []string{"header", "header"}); apperror.CodeOf(err) != "backend.identity.menu_assignment_duplicate" {
		t.Fatalf("duplicate=%v", err)
	}
	if err := service.ValidateRoleMenus(ctx, "role", []string{"missing"}); apperror.CodeOf(err) != "backend.identity.menu_not_active" {
		t.Fatalf("missing menu=%v", err)
	}
	for _, menuID := range []string{"disabled", "deleted"} {
		if err := service.ValidateRoleMenus(ctx, "role", []string{menuID}); apperror.CodeOf(err) != "backend.identity.menu_not_active" {
			t.Fatalf("%s menu=%v", menuID, err)
		}
	}
	if err := service.ValidateRoleMenus(ctx, "role", []string{"unknown-route"}); apperror.CodeOf(err) != "backend.identity.menu_route_not_registered" {
		t.Fatalf("unknown route=%v", err)
	}
	if err := service.ValidateRoleMenus(ctx, "role", []string{"literal-business-path"}); apperror.CodeOf(err) != "backend.identity.menu_route_not_registered" {
		t.Fatalf("literal business path=%v", err)
	}
	if err := service.ValidateRoleMenus(ctx, "role", []string{"business-members"}); err != nil {
		t.Fatalf("business route must not require a Surface permission: %v", err)
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "role"}})
	if err := service.ValidateRoleMenus(ctx, "role", []string{"account"}); apperror.CodeOf(err) != "backend.identity.menu_route_permission_missing" {
		t.Fatalf("missing permission=%v", err)
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "role", Permissions: []string{"identity.users.read"}}})
	if err := service.SetRoleMenus(ctx, "role", []string{"account"}); err != nil {
		t.Fatalf("valid role menus=%v", err)
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "role"}})
	if err := service.SetRoleMenus(ctx, "role", []string{"business-members"}); err != nil {
		t.Fatalf("valid business route key=%v", err)
	}
}
