package identitysdkadapter

import (
	"context"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type sdkApplications struct{ binding *sdkBinding }

func (adapter sdkApplications) Register(ctx context.Context, request identitysdk.ApplicationRegistration) (identitysdk.ApplicationRegistrationReceipt, error) {
	if err := request.ValidateContract(); err != nil {
		return identitysdk.ApplicationRegistrationReceipt{}, sdkBoundaryError(err)
	}
	if adapter.binding == nil || adapter.binding.applications == nil {
		return identitysdk.ApplicationRegistrationReceipt{}, &identitysdk.Error{Code: "identity.application_registry_unavailable"}
	}
	if string(request.Application.WorkspaceID) != adapter.binding.applications.WorkspaceID() {
		return identitysdk.ApplicationRegistrationReceipt{}, &identitysdk.Error{Code: "identity.application_scope_mismatch"}
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, request.Application.WorkspaceID); err != nil {
		return identitysdk.ApplicationRegistrationReceipt{}, err
	}
	registration, err := adapter.binding.applications.Register(ctx, string(request.Application.ApplicationKey), request.CanonicalRedirectURLs())
	if err != nil {
		return identitysdk.ApplicationRegistrationReceipt{}, sdkBoundaryError(err)
	}
	return identitysdk.ApplicationRegistrationReceipt{
		Application:  request.Application,
		RedirectURLs: append([]string(nil), registration.RedirectURLs...),
		Status:       strings.TrimSpace(registration.Status),
		UpdatedAt:    strings.TrimSpace(registration.UpdatedAt),
	}, nil
}
