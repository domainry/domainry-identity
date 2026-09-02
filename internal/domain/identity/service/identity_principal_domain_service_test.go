// Principal domain service tests.
package service

import (
	"reflect"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityPrincipalDomainServiceUsesRolesAndDefaultResolver(t *testing.T) {
	service := NewIdentityPrincipalDomainService(func() []identitymodel.RoleSchema {
		return []identitymodel.RoleSchema{{Key: "member", Permissions: []string{"customer.read"}}}
	}, func() string { return "member" })
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-primary")
	principal := service.Resolve(ctx, "user-1", "", "")
	if !principal.Known || principal.UserID != "user-1" || principal.Role.Key != "member" {
		t.Fatalf("principal=%#v", principal)
	}
	if !reflect.DeepEqual(principal.Role.Permissions, []string{"customer.read"}) {
		t.Fatalf("permissions=%v", principal.Role.Permissions)
	}
	if unknown := service.Resolve(ctx, "user-1", "missing", ""); unknown.Known {
		t.Fatalf("unknown=%#v", unknown)
	}
}

func TestIdentityPrincipalDomainServiceFailsClosedAndSupportsAlternateRole(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-primary")
	fallback := NewIdentityPrincipalDomainService(nil, nil).Resolve(ctx, "", "", "")
	if fallback.Known || fallback.UserID != "" || fallback.Role.Key != "" {
		t.Fatalf("fallback=%#v", fallback)
	}
	missingRole := NewIdentityPrincipalDomainService(nil, nil).Resolve(ctx, "user", "", "")
	if missingRole.Known || missingRole.UserID != "user" || missingRole.WorkspaceID != "workspace-primary" {
		t.Fatalf("missing role principal=%#v", missingRole)
	}
	service := NewIdentityPrincipalDomainService(func() []identitymodel.RoleSchema {
		return []identitymodel.RoleSchema{{Key: "alternate"}}
	}, nil)
	principal := service.Resolve(ctx, "user", "", " alternate ")
	if !principal.Known || principal.Role.Key != "alternate" {
		t.Fatalf("alternate=%#v", principal)
	}
}

func TestIdentityTreeScopeIDsIncludesRootAndAllDescendantsDeterministically(t *testing.T) {
	children := map[string][]string{
		"region":  {"store-b", "store-a"},
		"store-a": {"team"},
		"team":    {"region"}, // malformed cycle must not loop or duplicate IDs
	}
	if got, want := identityTreeScopeIDs("region", children), []string{"region", "store-a", "store-b", "team"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope IDs=%v want=%v", got, want)
	}
	if got := identityTreeScopeIDs("", children); len(got) != 0 {
		t.Fatalf("empty root scope IDs=%v", got)
	}
}

func TestResolvePrincipalScopeIDsDerivesActiveSupportOrganizationSubtree(t *testing.T) {
	supportRoot := "sales"
	disabledBranch := "sales-disabled"
	repository := &identityOrganizationUnitUserRepository{
		organizationUnits: []identitymodel.IdentityOrganizationUnit{
			{ID: "support", Status: identitymodel.IdentityStatusActive},
			{ID: supportRoot, Status: identitymodel.IdentityStatusActive},
			{ID: "sales-east", ParentID: &supportRoot, Status: identitymodel.IdentityStatusActive},
			{ID: disabledBranch, ParentID: &supportRoot, Status: identitymodel.IdentityStatusDisabled},
			{ID: "hidden-below-disabled", ParentID: &disabledBranch, Status: identitymodel.IdentityStatusActive},
		},
		users: []identitymodel.IdentityUser{{ID: "agent", Status: identitymodel.IdentityStatusActive}},
	}
	service := NewIdentityDomainService(repository, nil)
	orgIDs, supportIDs, reportingIDs, err := service.resolvePrincipalScopeIDs(t.Context(), "agent", "support", supportRoot)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"support"}; !reflect.DeepEqual(orgIDs, want) {
		t.Fatalf("primary organization scope=%v want=%v", orgIDs, want)
	}
	if want := []string{"sales", "sales-east"}; !reflect.DeepEqual(supportIDs, want) {
		t.Fatalf("support organization scope=%v want=%v", supportIDs, want)
	}
	if want := []string{"agent"}; !reflect.DeepEqual(reportingIDs, want) {
		t.Fatalf("reporting scope=%v want=%v", reportingIDs, want)
	}

	_, disabledIDs, _, err := service.resolvePrincipalScopeIDs(t.Context(), "agent", "support", disabledBranch)
	if err != nil || len(disabledIDs) != 0 {
		t.Fatalf("disabled support root scope=%v err=%v", disabledIDs, err)
	}
	_, missingIDs, _, err := service.resolvePrincipalScopeIDs(t.Context(), "agent", "support", "missing")
	if err != nil || len(missingIDs) != 0 {
		t.Fatalf("missing support root scope=%v err=%v", missingIDs, err)
	}
}
