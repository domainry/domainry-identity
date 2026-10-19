// Package credentialemail is the host's narrow delivery boundary for Identity
// invitations and recovery codes. Plaintext belongs only to the delivery call.
package credentialemail

import "context"

type Message struct {
	ID, WorkspaceID, To, Subject, Text, ExpiresAt string
}

type Delivery interface {
	Ready(context.Context, string) error
	Send(context.Context, Message) error
}

type Receipt struct {
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at"`
}

type Challenge struct {
	State     string `json:"state"`
	ExpiresAt string `json:"expires_at"`
	RetryAt   string `json:"retry_at"`
}
