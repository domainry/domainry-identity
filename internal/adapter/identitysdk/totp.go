package identitysdkadapter

import (
	"context"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func (adapter sdkCredentials) ManageTOTP(ctx context.Context, request identitysdk.TOTPRequest) (identitysdk.TOTPResult, error) {
	principal, err := adapter.binding.auth.PrincipalFromBearer(ctx, "Bearer "+request.AccessToken, "")
	if err != nil {
		return identitysdk.TOTPResult{}, sdkBoundaryError(err)
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, identitysdk.WorkspaceID(principal.WorkspaceID)); err != nil {
		return identitysdk.TOTPResult{}, err
	}
	result, err := adapter.binding.auth.ManageTOTPForPrincipal(ctx, principal, authmodel.TOTPRequest{
		Operation: request.Operation, CurrentPassword: request.CurrentPassword, State: request.State, Code: request.Code,
	})
	return identitysdk.TOTPResult{Enabled: result.Enabled, State: result.State, SetupKey: result.SetupKey, OTPAuthURL: result.OTPAuthURL, ExpiresAt: result.ExpiresAt}, sdkBoundaryError(err)
}
