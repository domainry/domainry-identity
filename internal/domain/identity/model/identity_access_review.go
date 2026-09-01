package identitymodel

type IdentityAccessReviewStatus string

const (
	IdentityAccessReviewDraft     IdentityAccessReviewStatus = "draft"
	IdentityAccessReviewOpen      IdentityAccessReviewStatus = "open"
	IdentityAccessReviewCompleted IdentityAccessReviewStatus = "completed"
)

type IdentityAccessReviewDecision string

const (
	IdentityAccessReviewKeep        IdentityAccessReviewDecision = "keep"
	IdentityAccessReviewRevoke      IdentityAccessReviewDecision = "revoke"
	IdentityAccessReviewReduceScope IdentityAccessReviewDecision = "reduce_scope"
	IdentityAccessReviewSetExpiry   IdentityAccessReviewDecision = "set_expiry"
)

type IdentityAccessReview struct {
	ID          string                     `json:"id"`
	WorkspaceID string                     `json:"workspace_id"`
	PeriodStart string                     `json:"period_start"`
	PeriodEnd   string                     `json:"period_end"`
	DueAt       string                     `json:"due_at"`
	Status      IdentityAccessReviewStatus `json:"status"`
	CreatedBy   string                     `json:"created_by"`
	CreatedAt   string                     `json:"created_at"`
	UpdatedAt   string                     `json:"updated_at"`
	Items       []IdentityAccessReviewItem `json:"items"`
}

type IdentityAccessReviewItem struct {
	ID                 string                                `json:"id"`
	ReviewID           string                                `json:"review_id"`
	UserID             string                                `json:"user_id"`
	RoleID             string                                `json:"role_id"`
	RoleKey            string                                `json:"role_key"`
	WorkforceProfileID string                                `json:"workforce_profile_id,omitempty"`
	BindingKey         string                                `json:"binding_key,omitempty"`
	ProfileID          string                                `json:"profile_id,omitempty"`
	RiskLevel          IdentityRoleRiskLevel                 `json:"risk_level"`
	Priority           string                                `json:"priority"`
	PriorityReasons    []string                              `json:"priority_reasons,omitempty"`
	PermissionStates   []IdentityAccessReviewPermissionState `json:"permission_states,omitempty"`
	LastUsedAt         string                                `json:"last_used_at,omitempty"`
	Status             string                                `json:"status"`
	Decision           IdentityAccessReviewDecision          `json:"decision,omitempty"`
	ReplacementRoleID  string                                `json:"replacement_role_id,omitempty"`
	ExpiresAt          string                                `json:"expires_at,omitempty"`
	ReviewerID         string                                `json:"reviewer_id,omitempty"`
	Reason             string                                `json:"reason,omitempty"`
	DecidedAt          string                                `json:"decided_at,omitempty"`
	Version            int64                                 `json:"version"`
	CreatedAt          string                                `json:"created_at"`
	UpdatedAt          string                                `json:"updated_at"`
}

// IdentityAccessReviewPermissionState is a current-state projection. It is
// recomputed when reviews are read and is deliberately not a review-owned
// PermissionDefinition revision or publication record.
type IdentityAccessReviewPermissionState struct {
	PermissionKey    string `json:"permission_key"`
	State            string `json:"state"`
	DefinitionStatus string `json:"definition_status,omitempty"`
	Enabled          bool   `json:"enabled"`
	SourceOwner      string `json:"source_owner,omitempty"`
}

type IdentityAccessReviewCreateRequest struct {
	ID          string `json:"id"`
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`
	DueAt       string `json:"due_at"`
}

type IdentityAccessReviewDecisionRequest struct {
	Decision          IdentityAccessReviewDecision `json:"decision"`
	ReplacementRoleID string                       `json:"replacement_role_id,omitempty"`
	ExpiresAt         string                       `json:"expires_at,omitempty"`
	Reason            string                       `json:"reason"`
	ExpectedVersion   int64                        `json:"expected_version"`
	IdempotencyKey    string                       `json:"idempotency_key"`
}

type IdentityAccessReviewDecisionMutation struct {
	WorkspaceID        string
	ItemID             string
	ReviewerID         string
	Request            IdentityAccessReviewDecisionRequest
	RequestFingerprint string
}

type IdentityAccessReviewDecisionReceipt struct {
	ID                 string                   `json:"id"`
	WorkspaceID        string                   `json:"workspace_id"`
	ItemID             string                   `json:"item_id"`
	IdempotencyKey     string                   `json:"idempotency_key"`
	RequestFingerprint string                   `json:"request_fingerprint"`
	Item               IdentityAccessReviewItem `json:"item"`
	Replayed           bool                     `json:"replayed"`
	CreatedAt          string                   `json:"created_at"`
}
