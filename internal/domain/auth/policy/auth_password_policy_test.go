package policy

import (
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
)

func TestAuthValidatePasswordCompletePolicyMatrix(t *testing.T) {
	tests := []struct {
		name     string
		policy   AuthPasswordPolicy
		password string
		code     string
	}{
		{name: "default minimum", password: "short", code: "auth.password_too_short"},
		{name: "unicode rune minimum", policy: AuthPasswordPolicy{MinLength: 2}, password: "密码"},
		{name: "custom minimum", policy: AuthPasswordPolicy{MinLength: 9}, password: "Aa1!abcd", code: "auth.password_too_short"},
		{name: "upper missing", policy: AuthPasswordPolicy{MinLength: 1, RequireUpper: true}, password: "a1!", code: "auth.password_requires_upper"},
		{name: "lower missing", policy: AuthPasswordPolicy{MinLength: 1, RequireLower: true}, password: "A1!", code: "auth.password_requires_lower"},
		{name: "number missing", policy: AuthPasswordPolicy{MinLength: 1, RequireNumber: true}, password: "Aa!", code: "auth.password_requires_number"},
		{name: "symbol missing", policy: AuthPasswordPolicy{MinLength: 1, RequireSymbol: true}, password: "Aa1", code: "auth.password_requires_symbol"},
		{name: "all requirements", policy: AuthPasswordPolicy{MinLength: 5, RequireUpper: true, RequireLower: true, RequireNumber: true, RequireSymbol: true}, password: "Aa1! "},
		{name: "unicode symbol", policy: AuthPasswordPolicy{MinLength: 4, RequireUpper: true, RequireLower: true, RequireNumber: true, RequireSymbol: true}, password: "Aa1€"},
		{name: "requirements disabled", policy: AuthPasswordPolicy{MinLength: 1}, password: " "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := AuthValidatePassword(test.policy, test.password)
			if test.code == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if got := apperror.CodeOf(err); got != test.code {
				t.Fatalf("code = %q, want %q (err=%v)", got, test.code, err)
			}
		})
	}
}
