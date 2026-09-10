// Package organizationunit preserves the public aliases for the SDK-owned delivery contract.
package organizationunit

import contract "github.com/domainry/domainry-identity-sdk/organizationunit"

type NodeType = contract.NodeType
type CreateCandidate = contract.CreateCandidate
type DeliveryRequest = contract.DeliveryRequest
type DeliveredOrganizationUnit = contract.DeliveredOrganizationUnit
type DeliveryResult = contract.DeliveryResult
type ResolveRequest = contract.ResolveRequest
type Delivery = contract.Delivery
type UnitOfWorkBinder = contract.UnitOfWorkBinder
type Binding = contract.Binding
type EmbeddedBinding = contract.EmbeddedBinding

const (
	DeliveryContractVersionV1 = contract.DeliveryContractVersionV1
	DeliveryCreatePermission  = contract.DeliveryCreatePermission
	DeliveryResolvePermission = contract.DeliveryResolvePermission
	NodeTypeCompany           = contract.NodeTypeCompany
	NodeTypeRegion            = contract.NodeTypeRegion
	NodeTypeStore             = contract.NodeTypeStore
	NodeTypeDepartment        = contract.NodeTypeDepartment
	NodeTypeTeam              = contract.NodeTypeTeam
	NodeTypeWarehouse         = contract.NodeTypeWarehouse
)
