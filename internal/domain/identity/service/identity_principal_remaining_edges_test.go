package service

import (
	"errors"
	"reflect"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestBuildPrincipalPropagatesOrganizationAndBindingResolutionErrors(t *testing.T) {
	repository := &identityPrincipalRoleRepository{
		identityRolesRepositoryStub: &identityRolesRepositoryStub{
			users: []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
			roles: []identitymodel.IdentityRole{{ID: "role", Key: "member", Status: identitymodel.IdentityStatusActive}},
			assignments: []identitymodel.IdentityUserRoleAssignment{{
				UserID: "user", RoleID: "role", BindingKey: "employment", ProfileID: "profile",
			}},
		},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{{
			ID: "workforce", IdentityUserID: "user", WorkStatus: identitymodel.IdentityWorkActive,
		}},
	}
	service := principalRoleService(t, repository)
	scopeFailure := errors.New("scope unavailable")
	service.UseOrganizationScopeResolver(&identityOrganizationScopeResolverStub{err: scopeFailure})
	if _, err := service.BuildPrincipal(t.Context(), "user"); !errors.Is(err, scopeFailure) {
		t.Fatalf("scope err=%v", err)
	}

	service.UseOrganizationScopeResolver(nil)
	bindingFailure := errors.New("binding unavailable")
	service.UseRoleBindingEligibility(identityRoleBindingEligibilityStub{err: bindingFailure})
	if _, err := service.BuildPrincipal(t.Context(), "user"); !errors.Is(err, bindingFailure) {
		t.Fatalf("principal binding err=%v", err)
	}
	if _, err := service.BuildPrincipalForRole(t.Context(), "user", "member"); !errors.Is(err, bindingFailure) {
		t.Fatalf("role binding err=%v", err)
	}

	service.UseRoleBindingEligibility(nil)
	repository.listAssignmentsErr = errors.New("assignments unavailable")
	repository.listAssignmentsFailAt = repository.listAssignmentsCalls + 1
	if _, err := service.BuildPrincipalForRole(t.Context(), "user", "member"); !errors.Is(err, repository.listAssignmentsErr) {
		t.Fatalf("assignment list err=%v", err)
	}
}

func TestBuildPrincipalAndSelectedRoleCoverPublicationAndAssignmentEdges(t *testing.T) {
	repository := &identityPrincipalRoleRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{
		users: []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{
			{ID: "empty-status", Key: "member"},
			{ID: "active", Key: "operator", Status: identitymodel.IdentityStatusActive},
		},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "empty-status"}},
	}}
	service := principalRoleService(t, repository)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "member", Permissions: []string{" ", "order.read"}, RecordScope: "all_records",
	}, {
		Key: "operator", RecordScope: "all_records",
	}})
	principal, err := service.BuildPrincipal(t.Context(), "user")
	if err != nil || !principal.Known || !reflect.DeepEqual(principal.Role.Permissions, []string{"order.read"}) {
		t.Fatalf("principal=%#v err=%v", principal, err)
	}
	selected, err := service.BuildPrincipalForRole(t.Context(), "user", "member")
	if err != nil || !selected.Known {
		t.Fatalf("selected=%#v err=%v", selected, err)
	}

	repository.assignments = []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "other"}}
	if selected, err = service.BuildPrincipalForRole(t.Context(), "user", "member"); err != nil || selected.Known {
		t.Fatalf("wrong-role assignment selected=%#v err=%v", selected, err)
	}
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "empty-status", Status: "disabled"}}
	if selected, err = service.BuildPrincipalForRole(t.Context(), "user", "member"); err != nil || selected.Known {
		t.Fatalf("inactive assignment selected=%#v err=%v", selected, err)
	}
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "empty-status"}}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "operator"}})
	if selected, err = service.BuildPrincipalForRole(t.Context(), "user", "member"); err != nil || selected.Known {
		t.Fatalf("unpublished role selected=%#v err=%v", selected, err)
	}
}

func TestIdentityPrincipalHelpersCoverBindingCollectionAndCloneEdges(t *testing.T) {
	service := &IdentityDomainService{workspace: "workspace-1"}
	now := time.Now()
	for _, tc := range []struct {
		name       string
		assignment identitymodel.IdentityUserRoleAssignment
		resolver   IdentityRoleBindingEligibilityResolver
		want       bool
	}{
		{name: "unbound", assignment: identitymodel.IdentityUserRoleAssignment{}, want: true},
		{name: "binding only", assignment: identitymodel.IdentityUserRoleAssignment{BindingKey: "employment"}},
		{name: "profile only", assignment: identitymodel.IdentityUserRoleAssignment{ProfileID: "profile"}},
		{name: "resolver missing", assignment: identitymodel.IdentityUserRoleAssignment{BindingKey: "employment", ProfileID: "profile"}},
		{name: "resolved active", assignment: identitymodel.IdentityUserRoleAssignment{BindingKey: "employment", ProfileID: "profile"}, resolver: identityRoleBindingEligibilityStub{active: true}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service.UseRoleBindingEligibility(tc.resolver)
			active, err := service.identityRoleAssignmentActive(t.Context(), tc.assignment, nil, now)
			if err != nil || active != tc.want {
				t.Fatalf("active=%t err=%v", active, err)
			}
		})
	}

	if got := identityUniqueSortedStrings([]string{" b ", "", "a", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("unique sorted=%v", got)
	}
	scopeResolver := &identityOrganizationScopeResolverStub{}
	service.UseOrganizationScopeResolver(scopeResolver)
	if facts, err := service.resolveOrganizationScopes(t.Context(), map[string]bool{}); err != nil || !reflect.DeepEqual(facts, identitymodel.IdentityOrganizationScopeFacts{}) {
		t.Fatalf("empty organization scopes=%#v err=%v", facts, err)
	}
	role := identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{
		{Key: "z"}, {Key: "a"},
	}}
	identityCanonicalizeEffectiveRole(&role)
	if role.Guardrails[0].Key != "a" {
		t.Fatalf("guardrails=%#v", role.Guardrails)
	}
	if cloneIdentityPolicyExpression(nil) != nil {
		t.Fatal("nil policy clone was not nil")
	}
	policy := &identitymodel.IdentityPolicyExpression{
		Path:     []identitymodel.IdentityPolicyRelationSegment{{Direction: "out"}},
		Values:   []string{"one"},
		Children: []identitymodel.IdentityPolicyExpression{{Values: []string{"child"}}},
	}
	cloned := cloneIdentityPolicyExpression(policy)
	policy.Path[0].Direction = "changed"
	policy.Values[0] = "changed"
	policy.Children[0].Values[0] = "changed"
	if cloned.Path[0].Direction != "out" || cloned.Values[0] != "one" || cloned.Children[0].Values[0] != "child" {
		t.Fatalf("policy clone=%#v", cloned)
	}
	mask := &identitymodel.FieldMaskStrategy{Type: "last_n", LastN: 4}
	rules := []identitymodel.ContextualFieldPolicyRule{{
		Actions: []string{"read"}, Predicate: cloned, MaskStrategy: mask,
	}, {
		Actions: []string{"write"},
	}}
	clonedRules := cloneContextualFieldPolicies(rules)
	rules[0].Actions[0] = "changed"
	rules[0].MaskStrategy.LastN = 1
	if clonedRules[0].Actions[0] != "read" || clonedRules[0].MaskStrategy.LastN != 4 || clonedRules[1].MaskStrategy != nil {
		t.Fatalf("rules clone=%#v", clonedRules)
	}
}
