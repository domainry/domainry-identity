package identitymodel

type IdentityHandlerUserOperation string
type IdentityHandlerLoginMode string

const (
	IdentityHandlerUserCreate    IdentityHandlerUserOperation = "create"
	IdentityHandlerUserUpdate    IdentityHandlerUserOperation = "update"
	IdentityHandlerUserDisable   IdentityHandlerUserOperation = "disable"
	IdentityHandlerLoginNone     IdentityHandlerLoginMode     = "none"
	IdentityHandlerLoginPassword IdentityHandlerLoginMode     = "password"
)

type IdentityHandlerDeliveryMutation struct {
	WorkspaceID          string
	ActorID              string
	IdempotencyKey       string
	RequestFingerprint   string
	Operation            IdentityHandlerUserOperation
	User                 IdentityUser
	RelatedUserUpdates   []IdentityUser
	ExpectedVersion      int64
	DataScope            IdentityDataScopeFilter
	RoleAssignments      []IdentityUserRoleAssignment
	RoleKeys             []string
	Credential           *IdentityCredential
	ProfileBinding       *IdentityProfileBindingMutation
	ProfileBindingResult *IdentityProfileBinding
	RevokeUserIDs        []string
}

type IdentityHandlerDeliveryResult struct {
	DeliveryID         string                  `json:"delivery_id"`
	User               IdentityUser            `json:"user"`
	RoleKeys           []string                `json:"role_keys"`
	ProfileBinding     *IdentityProfileBinding `json:"profile_binding,omitempty"`
	RevokedSessions    int                     `json:"revoked_sessions"`
	Replayed           bool                    `json:"replayed"`
	InitialPassword    string                  `json:"-"`
	MustChangePassword bool                    `json:"-"`
	NoStore            bool                    `json:"-"`
}

type IdentityHandlerDeliveryReceipt struct {
	WorkspaceID        string
	ActorID            string
	IdempotencyKey     string
	RequestFingerprint string
	Result             IdentityHandlerDeliveryResult
	CreatedAt          string
}
