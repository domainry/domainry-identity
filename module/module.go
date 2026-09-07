// Package module exposes the stable in-process Identity module factory.
// Implementation details remain under internal/assembly/module.
package module

import moduleassembly "github.com/domainry/domainry-identity/internal/assembly/module"
import organizationunit "github.com/domainry/domainry-identity/organizationunit"

const IdentityPortabilityProviderKey = moduleassembly.IdentityPortabilityProviderKey

type Options = moduleassembly.Options
type Factory = moduleassembly.Factory

// Organization-unit delivery aliases keep the public module facade thin while
// exposing the optional in-process capability to embedding Runtime versions.
type OrganizationUnitNodeType = organizationunit.NodeType
type OrganizationUnitCreateCandidate = organizationunit.CreateCandidate
type OrganizationUnitDeliveryRequest = organizationunit.DeliveryRequest
type DeliveredOrganizationUnit = organizationunit.DeliveredOrganizationUnit
type OrganizationUnitDeliveryResult = organizationunit.DeliveryResult
type OrganizationUnitResolveRequest = organizationunit.ResolveRequest
type OrganizationUnitDelivery = organizationunit.Delivery
type OrganizationUnitDeliveryUnitOfWorkBinder = organizationunit.UnitOfWorkBinder
type EmbeddedOrganizationUnitDeliveryBinding = organizationunit.EmbeddedBinding

const (
	OrganizationUnitDeliveryContractVersionV1 = organizationunit.DeliveryContractVersionV1
	OrganizationUnitDeliveryCreatePermission  = organizationunit.DeliveryCreatePermission
	OrganizationUnitDeliveryResolvePermission = organizationunit.DeliveryResolvePermission
	OrganizationUnitCompany                   = organizationunit.NodeTypeCompany
	OrganizationUnitRegion                    = organizationunit.NodeTypeRegion
	OrganizationUnitStore                     = organizationunit.NodeTypeStore
	OrganizationUnitDepartment                = organizationunit.NodeTypeDepartment
	OrganizationUnitTeam                      = organizationunit.NodeTypeTeam
	OrganizationUnitWarehouse                 = organizationunit.NodeTypeWarehouse
)

func OptionsFromEnvironment() Options { return moduleassembly.OptionsFromEnvironment() }

func NewFactory(options Options) *Factory { return moduleassembly.NewFactory(options) }
