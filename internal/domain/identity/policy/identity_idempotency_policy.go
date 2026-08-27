package policy

import "time"

const (
	IdentityMutationSuccessReceiptRetention = 30 * 24 * time.Hour
	IdentityMutationFailureReceiptRetention = 7 * 24 * time.Hour
)

// IdentityMutationReplay deliberately contains only stable mutation outcome
// data and never snapshots permissions, sessions, credentials, or tokens.
type IdentityMutationReplay struct {
	ResourceID string `json:"resource_id,omitempty"`
	Status     string `json:"status"`
}
