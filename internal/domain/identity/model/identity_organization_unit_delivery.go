package identitymodel

type IdentityOrganizationUnitDeliveryState struct {
	WorkspaceID      string
	OrganizationID   string
	Version          int64
	StateFingerprint string
	UpdatedAt        string
}

type IdentityOrganizationUnitDeliveryMutation struct {
	WorkspaceID        string
	ActorID            string
	IdempotencyKey     string
	RequestFingerprint string
	Organization       IdentityOrganizationUnit
	ExpectedVersion    int64
	DataScope          IdentityDataScopeFilter
}

type IdentityDeliveredOrganizationUnit struct {
	ID                   string                       `json:"id"`
	Code                 string                       `json:"code"`
	Name                 string                       `json:"name"`
	NodeType             IdentityOrganizationUnitType `json:"node_type"`
	Status               string                       `json:"status"`
	ParentOrganizationID string                       `json:"parent_organization_id"`
	Path                 string                       `json:"path"`
	AncestorIDs          []string                     `json:"ancestor_ids"`
	Depth                int                          `json:"depth"`
	SortOrder            int                          `json:"sort_order"`
	Version              int64                        `json:"version"`
}

type IdentityOrganizationUnitDeliveryResult struct {
	DeliveryID   string                            `json:"delivery_id"`
	Organization IdentityDeliveredOrganizationUnit `json:"organization"`
	Replayed     bool                              `json:"replayed"`
}

type IdentityOrganizationUnitDeliveryReceipt struct {
	WorkspaceID        string
	ActorID            string
	IdempotencyKey     string
	RequestFingerprint string
	Result             IdentityOrganizationUnitDeliveryResult
	CreatedAt          string
}
