package identitymodel

type IdentityProfileBindingStatus string

const (
	IdentityProfileBindingUnbound   IdentityProfileBindingStatus = "unbound"
	IdentityProfileBindingInvited   IdentityProfileBindingStatus = "invited"
	IdentityProfileBindingClaimed   IdentityProfileBindingStatus = "claimed"
	IdentityProfileBindingActive    IdentityProfileBindingStatus = "active"
	IdentityProfileBindingSuspended IdentityProfileBindingStatus = "suspended"
	IdentityProfileBindingUnlinked  IdentityProfileBindingStatus = "unlinked"
)

type IdentityProfileBindingOperation string

const (
	IdentityProfileBindingInvite IdentityProfileBindingOperation = "invite"
	IdentityProfileBindingClaim  IdentityProfileBindingOperation = "claim"
	IdentityProfileBindingBind   IdentityProfileBindingOperation = "bind"
	IdentityProfileBindingRebind IdentityProfileBindingOperation = "rebind"
	IdentityProfileBindingUnlink IdentityProfileBindingOperation = "unlink"
)

type IdentityProfileBinding struct {
	WorkspaceID       string                       `json:"workspace_id"`
	BindingKey        string                       `json:"binding_key"`
	ObjectKey         string                       `json:"object_key"`
	ProfileID         string                       `json:"profile_id"`
	IdentityUserID    string                       `json:"identity_user_id,omitempty"`
	Status            IdentityProfileBindingStatus `json:"status"`
	InvitationChannel string                       `json:"invitation_channel,omitempty"`
	ClaimProofType    string                       `json:"claim_proof_type,omitempty"`
	Version           int64                        `json:"version"`
	CreatedAt         string                       `json:"created_at"`
	UpdatedAt         string                       `json:"updated_at"`
}

type IdentityProfileBindingMutation struct {
	WorkspaceID          string                          `json:"workspace_id"`
	BindingKey           string                          `json:"binding_key"`
	ObjectKey            string                          `json:"object_key"`
	ProfileID            string                          `json:"profile_id"`
	IdentityField        string                          `json:"identity_field"`
	Operation            IdentityProfileBindingOperation `json:"operation"`
	IdentityUserID       string                          `json:"identity_user_id,omitempty"`
	InvitationChannel    string                          `json:"invitation_channel,omitempty"`
	ClaimProofType       string                          `json:"claim_proof_type,omitempty"`
	Reason               string                          `json:"reason,omitempty"`
	ApprovalID           string                          `json:"approval_id,omitempty"`
	SystemManagedRoleIDs []string                        `json:"system_managed_role_ids,omitempty"`
	ExpectedVersion      int64                           `json:"expected_version"`
	IdempotencyKey       string                          `json:"idempotency_key"`
	RequestFingerprint   string                          `json:"request_fingerprint"`
	ActorID              string                          `json:"actor_id"`
}

type IdentityProfileBindingReceipt struct {
	ID                 string                          `json:"id"`
	WorkspaceID        string                          `json:"workspace_id"`
	BindingKey         string                          `json:"binding_key"`
	ObjectKey          string                          `json:"object_key"`
	ProfileID          string                          `json:"profile_id"`
	Operation          IdentityProfileBindingOperation `json:"operation"`
	IdempotencyKey     string                          `json:"idempotency_key"`
	RequestFingerprint string                          `json:"request_fingerprint"`
	Binding            IdentityProfileBinding          `json:"binding"`
	Replayed           bool                            `json:"replayed"`
	CreatedAt          string                          `json:"created_at"`
}

type IdentityProfileBindingEvent struct {
	ID             string                          `json:"id"`
	WorkspaceID    string                          `json:"workspace_id"`
	BindingKey     string                          `json:"binding_key"`
	ObjectKey      string                          `json:"object_key"`
	ProfileID      string                          `json:"profile_id"`
	Operation      IdentityProfileBindingOperation `json:"operation"`
	PreviousUserID string                          `json:"previous_user_id,omitempty"`
	IdentityUserID string                          `json:"identity_user_id,omitempty"`
	BindingVersion int64                           `json:"binding_version"`
	IdempotencyKey string                          `json:"idempotency_key"`
	ActorID        string                          `json:"actor_id"`
	Reason         string                          `json:"reason,omitempty"`
	ApprovalID     string                          `json:"approval_id,omitempty"`
	Status         string                          `json:"status"`
	CreatedAt      string                          `json:"created_at"`
}
