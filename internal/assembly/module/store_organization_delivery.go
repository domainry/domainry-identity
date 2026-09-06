package moduleassembly

import (
	"context"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
)

type moduleStoreOrganizationDelivery struct {
	binding *moduleBinding
	tx      identitytransaction.Executor
}

type moduleStoreOrganizationDeliveryBinder struct {
	binding *moduleBinding
}

func (binding *moduleBinding) StoreOrganizationDeliveryUnitOfWorkBinder() identitysdk.StoreOrganizationDeliveryUnitOfWorkBinder {
	return moduleStoreOrganizationDeliveryBinder{binding: binding}
}

func (binder moduleStoreOrganizationDeliveryBinder) BindStoreOrganizationDeliveryUnitOfWork(transaction identitysdk.EmbeddedTransaction) (identitysdk.StoreOrganizationDelivery, error) {
	tx, ok := embeddedTransactionExecutor(transaction)
	if !ok {
		return nil, &identitysdk.Error{Code: "identity.store_organization_delivery_transaction_required"}
	}
	return moduleStoreOrganizationDelivery{binding: binder.binding, tx: tx}, nil
}

func (adapter moduleStoreOrganizationDelivery) DeliverStoreOrganization(ctx context.Context, request identitysdk.StoreOrganizationDeliveryRequest) (identitysdk.StoreOrganizationDeliveryResult, error) {
	provider, err := adapter.provider(ctx, request.AccessToken)
	if err != nil {
		return identitysdk.StoreOrganizationDeliveryResult{}, err
	}
	return provider.DeliverStoreOrganization(identitytransaction.WithExecutor(ctx, adapter.tx), request)
}

func (adapter moduleStoreOrganizationDelivery) ResolveStoreOrganization(ctx context.Context, request identitysdk.StoreOrganizationResolveRequest) (identitysdk.StoreOrganization, error) {
	provider, err := adapter.provider(ctx, request.AccessToken)
	if err != nil {
		return identitysdk.StoreOrganization{}, err
	}
	return provider.ResolveStoreOrganization(identitytransaction.WithExecutor(ctx, adapter.tx), request)
}

func (adapter moduleStoreOrganizationDelivery) ListStoreOrganizations(ctx context.Context, request identitysdk.StoreOrganizationListRequest) (identitysdk.StoreOrganizationPage, error) {
	provider, err := adapter.provider(ctx, request.AccessToken)
	if err != nil {
		return identitysdk.StoreOrganizationPage{}, err
	}
	return provider.ListStoreOrganizations(identitytransaction.WithExecutor(ctx, adapter.tx), request)
}

func (adapter moduleStoreOrganizationDelivery) provider(ctx context.Context, accessToken string) (identitysdk.StoreOrganizationDelivery, error) {
	if adapter.binding == nil || adapter.binding.runtime == nil || adapter.binding.runtime.Auth == nil || adapter.binding.runtime.Binding == nil || adapter.tx == nil {
		return nil, &identitysdk.Error{Code: "identity.store_organization_delivery_unavailable"}
	}
	claims, err := adapter.binding.runtime.Auth.VerifyAccessToken(ctx, strings.TrimSpace(accessToken))
	if err != nil {
		return nil, err
	}
	if claims.WorkspaceID != string(adapter.binding.application.WorkspaceID) || claims.Audience != string(adapter.binding.application.ApplicationKey) {
		return nil, &identitysdk.Error{Code: "identity.store_organization_delivery_application_scope_mismatch"}
	}
	binding, ok := adapter.binding.runtime.Binding.(identitysdk.StoreOrganizationDeliveryBinding)
	if !ok || binding.StoreOrganizationDelivery() == nil {
		return nil, &identitysdk.Error{Code: "identity.store_organization_delivery_unavailable"}
	}
	return binding.StoreOrganizationDelivery(), nil
}

var _ identitysdk.StoreOrganizationDelivery = moduleStoreOrganizationDelivery{}
var _ identitysdk.StoreOrganizationDeliveryUnitOfWorkBinder = moduleStoreOrganizationDeliveryBinder{}
var _ identitysdk.EmbeddedStoreOrganizationDeliveryBinding = (*moduleBinding)(nil)
