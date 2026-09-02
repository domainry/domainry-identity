package identitymodel

const (
	IdentityEntitlementOperationGrant  = "grant"
	IdentityEntitlementOperationRevoke = "revoke"
)

type IdentityEntitlementBatchItem struct {
	Operation  string `json:"operation"`
	UserID     string `json:"user_id"`
	RoleID     string `json:"role_id"`
	BindingKey string `json:"binding_key,omitempty"`
	ProfileID  string `json:"profile_id,omitempty"`
	ValidFrom  string `json:"valid_from,omitempty"`
	ValidUntil string `json:"valid_until,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type IdentityEntitlementBatchMutation struct {
	WorkspaceID        string                         `json:"workspace_id"`
	ActorID            string                         `json:"actor_id"`
	IdempotencyKey     string                         `json:"idempotency_key"`
	RequestFingerprint string                         `json:"request_fingerprint"`
	Items              []IdentityEntitlementBatchItem `json:"items"`
	Assignments        []IdentityUserRoleAssignment   `json:"assignments"`
}

type IdentityEntitlementBatchReceipt struct {
	ID                 string                         `json:"id"`
	WorkspaceID        string                         `json:"workspace_id"`
	ActorID            string                         `json:"actor_id"`
	IdempotencyKey     string                         `json:"idempotency_key"`
	RequestFingerprint string                         `json:"request_fingerprint"`
	Items              []IdentityEntitlementBatchItem `json:"items"`
	Replayed           bool                           `json:"replayed,omitempty"`
	CreatedAt          string                         `json:"created_at"`
}
