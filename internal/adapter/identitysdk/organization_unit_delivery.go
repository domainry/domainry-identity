package identitysdkadapter

import (
	"context"
	"net/http"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	organizationunit "github.com/domainry/domainry-identity/organizationunit"
)

type sdkOrganizationUnitDelivery struct {
	binding *sdkBinding
}

func (binding *sdkBinding) OrganizationUnitDelivery() organizationunit.Delivery {
	return sdkOrganizationUnitDelivery{binding: binding}
}

func (adapter sdkOrganizationUnitDelivery) CreateOrganizationUnit(ctx context.Context, request organizationunit.DeliveryRequest) (organizationunit.DeliveryResult, error) {
	if adapter.binding == nil || adapter.binding.organizationUnits == nil {
		return organizationunit.DeliveryResult{}, organizationUnitDeliveryUnavailableError()
	}
	result, err := adapter.binding.organizationUnits.Create(ctx, identityapplication.IdentityOrganizationUnitDeliveryRequest{
		ContractVersion: request.ContractVersion, AccessToken: request.AccessToken, IdempotencyKey: request.IdempotencyKey,
		OrganizationID: request.Organization.OrganizationID, Code: request.Organization.Code, Name: request.Organization.Name,
		NodeType: identitymodel.IdentityOrganizationUnitType(request.Organization.NodeType), ParentOrganizationID: request.Organization.ParentOrganizationID,
		SortOrder: request.Organization.SortOrder, ExpectedVersion: request.Organization.ExpectedVersion,
	})
	return sdkOrganizationUnitDeliveryResult(result), sdkBoundaryError(err)
}

func (adapter sdkOrganizationUnitDelivery) ResolveOrganizationUnit(ctx context.Context, request organizationunit.ResolveRequest) (organizationunit.DeliveredOrganizationUnit, error) {
	if adapter.binding == nil || adapter.binding.organizationUnits == nil {
		return organizationunit.DeliveredOrganizationUnit{}, organizationUnitDeliveryUnavailableError()
	}
	result, err := adapter.binding.organizationUnits.Resolve(ctx, identityapplication.IdentityOrganizationUnitResolveRequest{
		ContractVersion: request.ContractVersion, AccessToken: request.AccessToken, OrganizationID: request.OrganizationID,
		NodeType: identitymodel.IdentityOrganizationUnitType(request.NodeType),
	})
	return sdkDeliveredOrganizationUnit(result), sdkBoundaryError(err)
}

func sdkOrganizationUnitDeliveryResult(value identitymodel.IdentityOrganizationUnitDeliveryResult) organizationunit.DeliveryResult {
	return organizationunit.DeliveryResult{DeliveryID: value.DeliveryID, Organization: sdkDeliveredOrganizationUnit(value.Organization), Replayed: value.Replayed}
}

func sdkDeliveredOrganizationUnit(value identitymodel.IdentityDeliveredOrganizationUnit) organizationunit.DeliveredOrganizationUnit {
	return organizationunit.DeliveredOrganizationUnit{
		ID: value.ID, Code: value.Code, Name: value.Name, NodeType: organizationunit.NodeType(value.NodeType), Status: value.Status,
		ParentOrganizationID: value.ParentOrganizationID, Path: value.Path, AncestorIDs: append([]string(nil), value.AncestorIDs...),
		Depth: value.Depth, SortOrder: value.SortOrder, Version: value.Version,
	}
}

func organizationUnitDeliveryUnavailableError() *identitysdk.Error {
	return &identitysdk.Error{StatusCode: http.StatusInternalServerError, Code: "backend.identity.organization_unit_delivery_unavailable"}
}

var _ organizationunit.Delivery = sdkOrganizationUnitDelivery{}
var _ organizationunit.Binding = (*sdkBinding)(nil)
