package identitymodel

type IdentityStoreOrganizationOperation string

const (
	IdentityStoreOrganizationCreate  IdentityStoreOrganizationOperation = "create"
	IdentityStoreOrganizationRename  IdentityStoreOrganizationOperation = "rename"
	IdentityStoreOrganizationDisable IdentityStoreOrganizationOperation = "disable"
)

type IdentityStoreOrganizationState struct {
	WorkspaceID      string
	OrganizationID   string
	Version          int64
	StateFingerprint string
	UpdatedAt        string
}

type IdentityStoreOrganizationDeliveryMutation struct {
	WorkspaceID          string
	ActorID              string
	IdempotencyKey       string
	RequestFingerprint   string
	Operation            IdentityStoreOrganizationOperation
	Organization         IdentityOrganizationUnit
	RelatedOrganizations []IdentityOrganizationUnit
	ExpectedVersion      int64
	CurrentFingerprint   string
	DataScope            IdentityDataScopeFilter
}

type IdentityStoreOrganization struct {
	ID                   string   `json:"id"`
	Code                 string   `json:"code"`
	Name                 string   `json:"name"`
	Status               string   `json:"status"`
	ParentOrganizationID string   `json:"parent_organization_id"`
	Path                 string   `json:"path"`
	AncestorIDs          []string `json:"ancestor_ids"`
	Depth                int      `json:"depth"`
	SortOrder            int      `json:"sort_order"`
	Version              int64    `json:"version"`
}

type IdentityStoreOrganizationPage struct {
	Items      []IdentityStoreOrganization `json:"items"`
	NextCursor string                      `json:"next_cursor,omitempty"`
}

type IdentityStoreOrganizationDeliveryResult struct {
	DeliveryID   string                    `json:"delivery_id"`
	Organization IdentityStoreOrganization `json:"organization"`
	Replayed     bool                      `json:"replayed"`
}

type IdentityStoreOrganizationDeliveryReceipt struct {
	WorkspaceID        string
	ActorID            string
	IdempotencyKey     string
	RequestFingerprint string
	Result             IdentityStoreOrganizationDeliveryResult
	CreatedAt          string
}
