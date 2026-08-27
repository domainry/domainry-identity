package service

import (
	"strings"

	apperror "github.com/domainry/domainry-foundation/apperror"
)

func badRequest(code string, params ...string) error {
	return identityDomainError(apperror.KindBadRequest, code, params...)
}

func forbidden(code string, params ...string) error {
	return identityDomainError(apperror.KindForbidden, code, params...)
}

func conflict(code string, params ...string) error {
	return identityDomainError(apperror.KindConflict, code, params...)
}

func notFound(code string, params ...string) error {
	return identityDomainError(apperror.KindNotFound, code, params...)
}

func internalError(message string, cause error) error {
	return &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.internal", Params: map[string]string{"operation": message}, Err: cause}
}

func identityDomainError(kind apperror.ErrorKind, code string, params ...string) error {
	values := map[string]string{}
	for index := 0; index+1 < len(params); index += 2 {
		if key := strings.TrimSpace(params[index]); key != "" {
			values[key] = params[index+1]
		}
	}
	if len(values) == 0 {
		values = nil
	}
	return &apperror.AppError{Kind: kind, Code: code, Params: apperror.SanitizeParams(values)}
}

func valueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}
