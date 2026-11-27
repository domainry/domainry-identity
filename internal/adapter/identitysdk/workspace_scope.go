package identitysdkadapter

import (
	"context"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

func (binding *sdkBinding) forToken(ctx context.Context, token string) (*sdkBinding, error) {
	if binding.workspaceResolver == nil {
		return binding, nil
	}
	verified, err := binding.Tokens().Verify(ctx, identitysdk.VerifyTokenRequest{AccessToken: token})
	if err != nil {
		return nil, err
	}
	return binding.forApplication(ctx, identitysdk.ApplicationRef{WorkspaceID: verified.WorkspaceID, ApplicationKey: verified.Audience})
}

func (binding *sdkBinding) forApplication(ctx context.Context, application identitysdk.ApplicationRef) (*sdkBinding, error) {
	applications, err := binding.scopedApplications(ctx, application)
	if err != nil {
		return nil, err
	}
	clone := *binding
	clone.applications = applications
	clone.handlerDelivery = binding.handlerDelivery.ForWorkspace(string(application.WorkspaceID), applications)
	clone.organizationUnits = binding.organizationUnits.ForWorkspace(string(application.WorkspaceID), applications)
	return &clone, nil
}
