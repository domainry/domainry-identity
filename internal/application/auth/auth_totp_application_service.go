package auth

import (
	"context"

	"github.com/domainry/domainry-foundation/apperror"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// ManageTOTPForPrincipal keeps HTTP and embedded SDK enrollment on the same
// self-service authorization and audit boundary. No key or code enters audit.
func (s *AuthApplicationService) ManageTOTPForPrincipal(ctx context.Context, principal identitymodel.Principal, request authmodel.TOTPRequest) (authmodel.TOTPResult, error) {
	if !principal.Known || principal.UserID == "" {
		return authmodel.TOTPResult{}, apperror.New(apperror.KindForbidden, "auth.token_required", nil, nil)
	}
	result, err := s.AuthDomainService.ManageTOTP(ctx, principal.WorkspaceID, principal.UserID, request)
	if err == nil && request.Operation != "status" && s.audit != nil {
		s.audit(ctx, "auth_totp_"+request.Operation, "identity_user", principal.UserID, principal, "Updated authenticator app binding", nil, map[string]any{"enabled": result.Enabled}, nil)
	}
	return result, err
}
