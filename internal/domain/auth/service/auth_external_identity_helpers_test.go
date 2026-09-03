package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestNormalizedExternalAssertionClaims(t *testing.T) {
	assertion := authmodel.AuthExternalIdentityAssertion{
		Provider: " OIDC ", Subject: " subject ", Email: " user@example.com ", Phone: " 10086 ", DisplayName: " User ", Claims: map[string]string{"group": " sellers "},
	}
	tests := map[string]string{
		"provider":         "oidc",
		"subject":          "subject",
		"provider_subject": "subject",
		"email":            "user@example.com",
		"phone":            "10086",
		"mobile":           "10086",
		"display_name":     "User",
		"name":             "User",
		"group":            "sellers",
	}
	for claim, want := range tests {
		if got := normalizedAssertionClaim(assertion, " "+claim+" "); got != want {
			t.Errorf("claim %q: want %q, got %q", claim, want, got)
		}
	}
	assertion.Claims = nil
	if got := normalizedAssertionClaim(assertion, "unknown"); got != "" {
		t.Fatalf("unknown claim without claim map: %q", got)
	}
}

func TestExternalAssertionRoleMappingConditions(t *testing.T) {
	assertion := authmodel.AuthExternalIdentityAssertion{Email: "user@example.com", Claims: map[string]string{"group": "seller"}}
	tests := []struct {
		name    string
		mapping authmodel.AuthExternalRoleMapping
		want    bool
	}{
		{name: "missing claim", mapping: authmodel.AuthExternalRoleMapping{Match: "seller"}},
		{name: "missing match", mapping: authmodel.AuthExternalRoleMapping{Claim: "group"}},
		{name: "custom claim match", mapping: authmodel.AuthExternalRoleMapping{Claim: "group", Match: "seller"}, want: true},
		{name: "custom claim mismatch", mapping: authmodel.AuthExternalRoleMapping{Claim: "group", Match: "other"}},
		{name: "email domain match", mapping: authmodel.AuthExternalRoleMapping{Claim: "email_domain", Match: "example.com"}, want: true},
		{name: "email domain mismatch", mapping: authmodel.AuthExternalRoleMapping{Claim: "email_domain", Match: "other.example"}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := externalAssertionMappingMatches(assertion, testCase.mapping); got != testCase.want {
				t.Fatalf("want %v, got %v", testCase.want, got)
			}
		})
	}
	for _, email := range []string{"plain-address", "trailing@"} {
		assertion.Email = email
		if externalAssertionMappingMatches(assertion, authmodel.AuthExternalRoleMapping{Claim: "email_domain", Match: "example.com"}) {
			t.Fatalf("invalid email %q must not match a domain", email)
		}
	}
}

func TestExternalAutoAssignableRoleUsesDeclaredPolicy(t *testing.T) {
	tests := []struct {
		role identitymodel.RoleSchema
		want bool
	}{
		{role: identitymodel.RoleSchema{}, want: true},
		{role: identitymodel.RoleSchema{Key: "admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list")}, want: true},
		{role: identitymodel.RoleSchema{AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged}},
		{role: identitymodel.RoleSchema{Audience: identitymodel.IdentityRoleAudienceBusiness}},
		{role: identitymodel.RoleSchema{RiskLevel: identitymodel.IdentityRoleRiskPrivileged}},
	}
	for _, testCase := range tests {
		if got := externalAutoAssignableRole(testCase.role); got != testCase.want {
			t.Errorf("role %#v: want %v, got %v", testCase.role, testCase.want, got)
		}
	}
}
