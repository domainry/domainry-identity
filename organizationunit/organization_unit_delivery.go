// Package organizationunit defines the narrow, transaction-bound contract
// used by generated Runtime handlers to create and resolve Identity-owned
// organization units. It is intentionally separate from generic management
// CRUD: callers cannot move, rename, disable, or otherwise rewrite the tree.
package organizationunit

import (
	"context"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

const DeliveryContractVersionV1 = "domainry-identity-organization-unit-delivery-v1"

const (
	DeliveryCreatePermission  = "identity.organization_unit_delivery.create"
	DeliveryResolvePermission = "identity.organization_unit_delivery.resolve"
)

type NodeType string

const (
	NodeTypeCompany    NodeType = "company"
	NodeTypeRegion     NodeType = "region"
	NodeTypeStore      NodeType = "store"
	NodeTypeDepartment NodeType = "department"
	NodeTypeTeam       NodeType = "team"
	NodeTypeWarehouse  NodeType = "warehouse"
)

func (value NodeType) Valid() bool {
	switch value {
	case NodeTypeCompany, NodeTypeRegion, NodeTypeStore, NodeTypeDepartment, NodeTypeTeam, NodeTypeWarehouse:
		return true
	default:
		return false
	}
}

// ValidDeliveryChild reports whether V1 may create the type through the
// generic delivery capability. Company remains root-only and store retains its
// purpose-specific StoreOrganizationDelivery lifecycle and quota policy.
func (value NodeType) ValidDeliveryChild() bool {
	switch value {
	case NodeTypeRegion, NodeTypeDepartment, NodeTypeTeam, NodeTypeWarehouse:
		return true
	default:
		return false
	}
}

// CreateCandidate deliberately accepts only create-time facts. Identity owns
// status, path, ancestors, and depth. A parent is mandatory, so company (the
// root node type) is not accepted by V1; store also remains exclusively owned
// by StoreOrganizationDelivery.
type CreateCandidate struct {
	OrganizationID       string   `json:"organization_id"`
	Code                 string   `json:"code"`
	Name                 string   `json:"name"`
	NodeType             NodeType `json:"node_type"`
	ParentOrganizationID string   `json:"parent_organization_id"`
	SortOrder            int      `json:"sort_order,omitempty"`
	ExpectedVersion      int64    `json:"expected_version"`
}

type DeliveryRequest struct {
	ContractVersion string          `json:"contract_version"`
	AccessToken     string          `json:"-"`
	IdempotencyKey  string          `json:"idempotency_key"`
	Organization    CreateCandidate `json:"organization"`
}

// DeliveredOrganizationUnit contains only canonical, non-secret Identity
// facts. Version is the delivery aggregate's optimistic-concurrency evidence;
// V1 creates start at version 1.
type DeliveredOrganizationUnit struct {
	ID                   string   `json:"id"`
	Code                 string   `json:"code"`
	Name                 string   `json:"name"`
	NodeType             NodeType `json:"node_type"`
	Status               string   `json:"status"`
	ParentOrganizationID string   `json:"parent_organization_id"`
	Path                 string   `json:"path"`
	AncestorIDs          []string `json:"ancestor_ids"`
	Depth                int      `json:"depth"`
	SortOrder            int      `json:"sort_order"`
	Version              int64    `json:"version"`
}

type DeliveryResult struct {
	DeliveryID   string                    `json:"delivery_id"`
	Organization DeliveredOrganizationUnit `json:"organization"`
	Replayed     bool                      `json:"replayed"`
}

// ResolveRequest requires the expected type. Identity resolves and authorizes
// against the node's persisted active parent; callers neither discover nor
// supply a potentially forged parent ID.
type ResolveRequest struct {
	ContractVersion string   `json:"contract_version"`
	AccessToken     string   `json:"-"`
	OrganizationID  string   `json:"organization_id"`
	NodeType        NodeType `json:"node_type"`
}

type Delivery interface {
	CreateOrganizationUnit(context.Context, DeliveryRequest) (DeliveryResult, error)
	ResolveOrganizationUnit(context.Context, ResolveRequest) (DeliveredOrganizationUnit, error)
}

type UnitOfWorkBinder interface {
	BindOrganizationUnitDeliveryUnitOfWork(identitysdk.EmbeddedTransaction) (Delivery, error)
}

type Binding interface {
	OrganizationUnitDelivery() Delivery
}

type EmbeddedBinding interface {
	OrganizationUnitDeliveryUnitOfWorkBinder() UnitOfWorkBinder
}
