package identitymodel

type IdentityWorkforceTransferBatchItem struct {
	ProfileID            string                      `json:"profile_id"`
	PreviousAssignmentID string                      `json:"previous_assignment_id"`
	Assignment           IdentityWorkforceAssignment `json:"assignment"`
	EffectiveAt          string                      `json:"effective_at"`
	Reason               string                      `json:"reason,omitempty"`
}

type IdentityWorkforceTransferBatchMutation struct {
	WorkspaceID        string                               `json:"workspace_id"`
	ActorID            string                               `json:"actor_id"`
	IdempotencyKey     string                               `json:"idempotency_key"`
	RequestFingerprint string                               `json:"request_fingerprint"`
	Items              []IdentityWorkforceTransferBatchItem `json:"items"`
	Mutations          []IdentityWorkforceLifecycleMutation `json:"mutations"`
}

type IdentityWorkforceTransferBatchReceipt struct {
	ID                 string                               `json:"id"`
	WorkspaceID        string                               `json:"workspace_id"`
	ActorID            string                               `json:"actor_id"`
	IdempotencyKey     string                               `json:"idempotency_key"`
	RequestFingerprint string                               `json:"request_fingerprint"`
	Items              []IdentityWorkforceTransferBatchItem `json:"items"`
	Replayed           bool                                 `json:"replayed,omitempty"`
	CreatedAt          string                               `json:"created_at"`
}
