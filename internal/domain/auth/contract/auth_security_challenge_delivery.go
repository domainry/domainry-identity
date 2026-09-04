package contract

import "context"

type AuthSecurityChallengeDelivery interface {
	DeliverSecurityChallenge(context.Context, AuthSecurityChallengeDeliveryRequest) (AuthSecurityChallengeDeliveryReceipt, error)
}

type AuthSecurityChallengeDeliveryRequest struct {
	ChallengeID       string
	WorkspaceID       string
	ConnectionKey     string
	Channel           string
	Destination       string
	MaskedDestination string
	Message           string
	ExpiresAt         string
}

type AuthSecurityChallengeDeliveryReceipt struct {
	Status      string
	ResponseRef string
}
