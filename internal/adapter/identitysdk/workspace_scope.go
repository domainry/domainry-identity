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
	applications, err := binding.scopedApplications(ctx, identitysdk.ApplicationRef{WorkspaceID: verified.WorkspaceID, ApplicationKey: verified.Audience})
	if err != nil {
		return nil, err
	}
	clone := *binding
	clone.applications = applications
	clone.handlerDelivery = binding.handlerDelivery.ForWorkspace(string(verified.WorkspaceID), applications)
	clone.storeOrganizations = binding.storeOrganizations.ForWorkspace(string(verified.WorkspaceID), applications)
	clone.organizationUnits = binding.organizationUnits.ForWorkspace(string(verified.WorkspaceID), applications)
	return &clone, nil
}
