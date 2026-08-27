package policy

import (
	"unicode"

	"github.com/domainry/domainry-foundation/apperror"
)

type AuthPasswordPolicy struct {
	MinLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireNumber bool
	RequireSymbol bool
}

func AuthValidatePassword(policy AuthPasswordPolicy, password string) error {
	if policy.MinLength <= 0 {
		policy.MinLength = 8
	}
	if len([]rune(password)) < policy.MinLength {
		return authPasswordError("auth.password_too_short")
	}
	var hasUpper, hasLower, hasNumber, hasSymbol bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}
	if policy.RequireUpper && !hasUpper {
		return authPasswordError("auth.password_requires_upper")
	}
	if policy.RequireLower && !hasLower {
		return authPasswordError("auth.password_requires_lower")
	}
	if policy.RequireNumber && !hasNumber {
		return authPasswordError("auth.password_requires_number")
	}
	if policy.RequireSymbol && !hasSymbol {
		return authPasswordError("auth.password_requires_symbol")
	}
	return nil
}

func authPasswordError(code string) error {
	return &apperror.AppError{Kind: apperror.KindBadRequest, Code: code}
}
