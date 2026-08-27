package service

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityOrganizationScopeResolverStub struct {
	profiles []string
	facts    identitymodel.IdentityOrganizationScopeFacts
	err      error
}

func (s *identityOrganizationScopeResolverStub) ResolveIdentityOrganizationScopes(_ context.Context, workspace string, profiles []string) (identitymodel.IdentityOrganizationScopeFacts, error) {
	if workspace != "workspace-1" {
		return identitymodel.IdentityOrganizationScopeFacts{}, errors.New("wrong workspace")
	}
	s.profiles = append([]string(nil), profiles...)
	return s.facts, s.err
}

func TestBuildPrincipalUsesServerOrganizationScopeFacts(t *testing.T) {
	repository := &identityPrincipalRoleRepository{
		identityRolesRepositoryStub: &identityRolesRepositoryStub{
			users:       []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
			roles:       []identitymodel.IdentityRole{{ID: "role", Key: "member", Status: identitymodel.IdentityStatusActive}},
			assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "role"}},
		},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{{
			ID: "workforce", IdentityUserID: "user", WorkStatus: identitymodel.IdentityWorkActive,
		}},
		workforceAssignments: []identitymodel.IdentityWorkforceAssignment{{
			ID: "assignment", WorkforceProfileID: "workforce", OrganizationUnitID: "department",
			AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
		}},
	}
	service := principalRoleService(t, repository)
	resolver := &identityOrganizationScopeResolverStub{facts: identitymodel.IdentityOrganizationScopeFacts{
		TeamIDs: []string{"team"}, StoreIDs: []string{"store"}, TerritoryIDs: []string{"territory"}, WarehouseIDs: []string{"warehouse"},
	}}
	service.UseOrganizationScopeResolver(resolver)
	principal, err := service.BuildPrincipal(t.Context(), "user")
	if err != nil || !reflect.DeepEqual(resolver.profiles, []string{"workforce"}) ||
		!reflect.DeepEqual(principal.TeamIDs, []string{"team"}) ||
		!reflect.DeepEqual(principal.StoreIDs, []string{"store"}) ||
		!reflect.DeepEqual(principal.TerritoryIDs, []string{"territory"}) ||
		!reflect.DeepEqual(principal.WarehouseIDs, []string{"warehouse"}) {
		t.Fatalf("principal=%#v profiles=%#v err=%v", principal, resolver.profiles, err)
	}
	resolver.err = errors.New("scope failure")
	if _, err := service.BuildPrincipalForRole(t.Context(), "user", "member"); !errors.Is(err, resolver.err) {
		t.Fatalf("role principal error=%v", err)
	}
}
