package moduleassembly

import (
	"context"
	"fmt"

	identitymodulehost "github.com/domainry/domainry-identity-sdk/modulehost"
	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
)

type moduleSecurityChallengeDelivery struct {
	delivery identitymodulehost.SecurityChallengeDelivery
}

func (adapter moduleSecurityChallengeDelivery) DeliverSecurityChallenge(ctx context.Context, request authcontract.AuthSecurityChallengeDeliveryRequest) (authcontract.AuthSecurityChallengeDeliveryReceipt, error) {
	receipt, err := adapter.delivery.DeliverSecurityChallenge(ctx, identitymodulehost.SecurityChallengeDeliveryRequest{
		ChallengeID:       request.ChallengeID,
		WorkspaceID:       request.WorkspaceID,
		ConnectionKey:     request.ConnectionKey,
		Channel:           request.Channel,
		Destination:       request.Destination,
		MaskedDestination: request.MaskedDestination,
		Message:           request.Message,
		ExpiresAt:         request.ExpiresAt,
	})
	return authcontract.AuthSecurityChallengeDeliveryReceipt{Status: receipt.Status, ResponseRef: receipt.ResponseRef}, err
}

func (binding *moduleBinding) BindSecurityChallengeDelivery(delivery identitymodulehost.SecurityChallengeDelivery) error {
	if binding == nil || binding.runtime == nil || binding.runtime.ProviderFlows == nil {
		return fmt.Errorf("Identity module security challenge flow is unavailable")
	}
	if delivery == nil {
		return fmt.Errorf("security challenge delivery is required")
	}
	binding.runtime.ProviderFlows.UseSecurityChallengeDelivery(moduleSecurityChallengeDelivery{delivery: delivery})
	return nil
}

var _ authcontract.AuthSecurityChallengeDelivery = moduleSecurityChallengeDelivery{}
