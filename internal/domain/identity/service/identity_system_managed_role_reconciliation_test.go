package service

import (
	"context"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type businessProfileResolverStub struct {
	profiles []IdentityBusinessProfile
	calls    int
}

func (s *businessProfileResolverStub) ResolveIdentityBusinessProfiles(context.Context, string, string) ([]IdentityBusinessProfile, error) {
	s.calls++
	return append([]IdentityBusinessProfile(nil), s.profiles...), nil
}

func TestReconcileSystemManagedBusinessRolesPersistsOnlyMatchingPublishedRole(t *testing.T) {
	repository, service := identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged},
		{Key: "viewer", Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "admin", Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged, Permissions: identityTestRolePermissions("identity.roles.list"), RiskLevel: identitymodel.IdentityRoleRiskPrivileged},
	})
	resolver := &businessProfileResolverStub{profiles: []IdentityBusinessProfile{{BindingKey: "member", ProfileID: "member-1"}}}
	service.UseBusinessProfileResolver(resolver)

	if err := service.ReconcileSystemManagedBusinessRoles(t.Context(), "user-1"); err != nil {
		t.Fatal(err)
	}
	if len(repository.assigned) != 1 {
		t.Fatalf("assignments=%+v", repository.assigned)
	}
	if resolver.calls != 1 {
		t.Fatalf("business profile resolver calls=%d, want one authoritative projection", resolver.calls)
	}
	assignment := repository.assigned[0]
	if assignment.UserID != "user-1" || assignment.RoleID != "member-id" || assignment.BindingKey != "member" || assignment.ProfileID != "member-1" || assignment.Source != "profile_binding" {
		t.Fatalf("assignment=%+v", assignment)
	}
	principal, err := service.BuildPrincipal(t.Context(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Known {
		t.Fatalf("principal=%+v", principal)
	}
}
