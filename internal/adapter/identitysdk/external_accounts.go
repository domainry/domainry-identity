package identitysdkadapter

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type sdkExternalAccounts struct{ binding *sdkBinding }

func (adapter sdkExternalAccounts) ListExternalAccounts(ctx context.Context, request identitysdk.ListExternalAccountsRequest) ([]identitysdk.ExternalAccount, error) {
	claims, err := sdkActionAssurance{binding: adapter.binding}.userClaims(ctx, request.WorkspaceID, request.AccessToken)
	if err != nil {
		return nil, err
	}
	accounts, err := adapter.binding.auth.ListExternalAccounts(requestcontext.WithWorkspaceID(ctx, claims.WorkspaceID), claims.WorkspaceID, claims.Subject)
	if err != nil {
		return nil, sdkBoundaryError(err)
	}
	result := make([]identitysdk.ExternalAccount, 0, len(accounts))
	for _, account := range accounts {
		result = append(result, identitysdk.ExternalAccount{
			ID: account.ID, UserID: account.UserID, Provider: account.Provider, ProviderSubject: account.ProviderSubject,
			Email: account.Email, Phone: account.Phone, DisplayName: account.DisplayName, AvatarURL: account.AvatarURL, LinkedAt: account.LinkedAt,
		})
	}
	return result, nil
}

func (adapter sdkExternalAccounts) StartExternalAccountLink(ctx context.Context, request identitysdk.StartExternalAccountLinkRequest) (identitysdk.ProviderChallenge, error) {
	claims, err := sdkActionAssurance{binding: adapter.binding}.userClaims(ctx, request.WorkspaceID, request.AccessToken)
	if err != nil {
		return identitysdk.ProviderChallenge{}, err
	}
	workspaceID := identitysdk.WorkspaceID(claims.WorkspaceID)
	application := identitysdk.ApplicationRef{WorkspaceID: workspaceID, ApplicationKey: request.ApplicationKey}
	if !application.ApplicationKey.Valid() {
		return identitysdk.ProviderChallenge{}, &identitysdk.Error{Code: "identity.application_scope_invalid"}
	}
	flowContext := requestcontext.WithWorkspaceID(ctx, claims.WorkspaceID)
	if err := adapter.binding.requireMutableWorkspace(flowContext, workspaceID); err != nil {
		return identitysdk.ProviderChallenge{}, err
	}
	if found, err := adapter.binding.applicationRegistered(flowContext, application); err != nil {
		return identitysdk.ProviderChallenge{}, sdkBoundaryError(err)
	} else if !found {
		return identitysdk.ProviderChallenge{}, &identitysdk.Error{Code: "identity.application_not_registered"}
	}
	if err := adapter.binding.validateApplicationRedirect(flowContext, application, request.ReturnURL); err != nil {
		return identitysdk.ProviderChallenge{}, sdkBoundaryError(err)
	}
	result, err := adapter.binding.flows.StartExternalAccountLinkForApplication(
		flowContext, claims.WorkspaceID, claims.Subject, strings.TrimSpace(request.Provider), string(request.ApplicationKey), request.ReturnURL,
	)
	if err != nil {
		return identitysdk.ProviderChallenge{}, sdkBoundaryError(err)
	}
	return sdkProviderChallenge(result), nil
}

func (adapter sdkExternalAccounts) UnbindExternalAccount(ctx context.Context, request identitysdk.UnbindExternalAccountRequest) error {
	claims, err := sdkActionAssurance{binding: adapter.binding}.userClaims(ctx, request.WorkspaceID, request.AccessToken)
	if err != nil {
		return err
	}
	workspaceID := identitysdk.WorkspaceID(claims.WorkspaceID)
	flowContext := requestcontext.WithWorkspaceID(ctx, claims.WorkspaceID)
	if err := adapter.binding.requireMutableWorkspace(flowContext, workspaceID); err != nil {
		return err
	}
	return sdkBoundaryError(adapter.binding.auth.UnbindExternalAccount(flowContext, claims.WorkspaceID, claims.Subject, request.Provider, request.AccountID))
}

var _ identitysdk.ExternalAccountManager = sdkExternalAccounts{}
