package policy

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"testing"
)

func TestDefaultRoleSelectionIsStableAndHasNoBusinessNamePriority(t *testing.T) {
	cases := []struct {
		name  string
		roles []identitymodel.IdentityRole
		want  string
	}{
		{name: "empty"},
		{name: "empty key does not use role ID", roles: []identitymodel.IdentityRole{{ID: "admin"}}},
		{name: "business role names have no priority", roles: []identitymodel.IdentityRole{{Key: "owner"}, {Key: "admin"}, {Key: "accountant"}}, want: "accountant"},
		{name: "input order does not select role", roles: []identitymodel.IdentityRole{{Key: "member_onboarding"}, {Key: "member"}}, want: "member"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SelectDefaultRole(tc.roles); got != tc.want {
				t.Fatalf("role=%q want=%q", got, tc.want)
			}
			for i, j := 0, len(tc.roles)-1; i < j; i, j = i+1, j-1 {
				tc.roles[i], tc.roles[j] = tc.roles[j], tc.roles[i]
			}
			if got := SelectDefaultRole(tc.roles); got != tc.want {
				t.Fatalf("reordered role=%q want=%q", got, tc.want)
			}
		})
	}
}
