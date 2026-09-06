package identitysdkadapter

import (
	"context"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type sdkStoreOrganizationDelivery struct {
	binding *sdkBinding
}

func (binding *sdkBinding) StoreOrganizationDelivery() identitysdk.StoreOrganizationDelivery {
	return sdkStoreOrganizationDelivery{binding: binding}
}

func (adapter sdkStoreOrganizationDelivery) DeliverStoreOrganization(ctx context.Context, request identitysdk.StoreOrganizationDeliveryRequest) (identitysdk.StoreOrganizationDeliveryResult, error) {
	if adapter.binding == nil || adapter.binding.storeOrganizations == nil {
		return identitysdk.StoreOrganizationDeliveryResult{}, &identitysdk.Error{Code: "identity.store_organization_delivery_unavailable"}
	}
	claims, err := adapter.binding.auth.VerifyAccessToken(ctx, strings.TrimSpace(request.AccessToken))
	if err != nil {
		return identitysdk.StoreOrganizationDeliveryResult{}, sdkBoundaryError(err)
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, identitysdk.WorkspaceID(claims.WorkspaceID)); err != nil {
		return identitysdk.StoreOrganizationDeliveryResult{}, err
	}
	result, err := adapter.binding.storeOrganizations.Deliver(ctx, identityapplication.IdentityStoreOrganizationDeliveryRequest{
		ContractVersion: request.ContractVersion, AccessToken: request.AccessToken, IdempotencyKey: request.IdempotencyKey,
		Operation:      identitymodel.IdentityStoreOrganizationOperation(request.Organization.Operation),
		OrganizationID: request.Organization.OrganizationID, Code: request.Organization.Code, Name: request.Organization.Name,
		ParentOrganizationID: request.Organization.ParentOrganizationID, SortOrder: request.Organization.SortOrder,
		ExpectedVersion: request.Organization.ExpectedVersion,
	})
	return sdkStoreOrganizationDeliveryResult(result), sdkBoundaryError(err)
}

func (adapter sdkStoreOrganizationDelivery) ResolveStoreOrganization(ctx context.Context, request identitysdk.StoreOrganizationResolveRequest) (identitysdk.StoreOrganization, error) {
	if adapter.binding == nil || adapter.binding.storeOrganizations == nil {
		return identitysdk.StoreOrganization{}, &identitysdk.Error{Code: "identity.store_organization_delivery_unavailable"}
	}
	result, err := adapter.binding.storeOrganizations.Resolve(ctx, identityapplication.IdentityStoreOrganizationResolveRequest{
		ContractVersion: request.ContractVersion, AccessToken: request.AccessToken, OrganizationID: request.OrganizationID,
	})
	return sdkStoreOrganization(result), sdkBoundaryError(err)
}

func (adapter sdkStoreOrganizationDelivery) ListStoreOrganizations(ctx context.Context, request identitysdk.StoreOrganizationListRequest) (identitysdk.StoreOrganizationPage, error) {
	if adapter.binding == nil || adapter.binding.storeOrganizations == nil {
		return identitysdk.StoreOrganizationPage{}, &identitysdk.Error{Code: "identity.store_organization_delivery_unavailable"}
	}
	result, err := adapter.binding.storeOrganizations.List(ctx, identityapplication.IdentityStoreOrganizationListRequest{
		ContractVersion: request.ContractVersion, AccessToken: request.AccessToken, PageSize: request.PageSize, Cursor: request.Cursor,
	})
	if err != nil {
		return identitysdk.StoreOrganizationPage{}, sdkBoundaryError(err)
	}
	out := identitysdk.StoreOrganizationPage{Items: make([]identitysdk.StoreOrganization, len(result.Items)), NextCursor: result.NextCursor}
	for index := range result.Items {
		out.Items[index] = sdkStoreOrganization(result.Items[index])
	}
	return out, nil
}

func sdkStoreOrganizationDeliveryResult(value identitymodel.IdentityStoreOrganizationDeliveryResult) identitysdk.StoreOrganizationDeliveryResult {
	return identitysdk.StoreOrganizationDeliveryResult{DeliveryID: value.DeliveryID, Organization: sdkStoreOrganization(value.Organization), Replayed: value.Replayed}
}

func sdkStoreOrganization(value identitymodel.IdentityStoreOrganization) identitysdk.StoreOrganization {
	return identitysdk.StoreOrganization{
		ID: value.ID, Code: value.Code, Name: value.Name, Status: value.Status, ParentOrganizationID: value.ParentOrganizationID,
		Path: value.Path, AncestorIDs: append([]string(nil), value.AncestorIDs...), Depth: value.Depth, SortOrder: value.SortOrder, Version: value.Version,
	}
}

var _ identitysdk.StoreOrganizationDelivery = sdkStoreOrganizationDelivery{}
var _ identitysdk.StoreOrganizationDeliveryBinding = (*sdkBinding)(nil)
