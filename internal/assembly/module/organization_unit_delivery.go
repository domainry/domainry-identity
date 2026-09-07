package moduleassembly

import (
	"context"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	organizationunit "github.com/domainry/domainry-identity/organizationunit"
)

type moduleOrganizationUnitDelivery struct {
	binding *moduleBinding
	tx      identitytransaction.Executor
}

type moduleOrganizationUnitDeliveryBinder struct {
	binding *moduleBinding
}

func (binding *moduleBinding) OrganizationUnitDeliveryUnitOfWorkBinder() organizationunit.UnitOfWorkBinder {
	return moduleOrganizationUnitDeliveryBinder{binding: binding}
}

func (binder moduleOrganizationUnitDeliveryBinder) BindOrganizationUnitDeliveryUnitOfWork(transaction identitysdk.EmbeddedTransaction) (organizationunit.Delivery, error) {
	tx, ok := embeddedTransactionExecutor(transaction)
	if !ok {
		return nil, &identitysdk.Error{Code: "identity.organization_unit_delivery_transaction_required"}
	}
	return moduleOrganizationUnitDelivery{binding: binder.binding, tx: tx}, nil
}

func (adapter moduleOrganizationUnitDelivery) CreateOrganizationUnit(ctx context.Context, request organizationunit.DeliveryRequest) (organizationunit.DeliveryResult, error) {
	provider, err := adapter.provider(ctx, request.AccessToken)
	if err != nil {
		return organizationunit.DeliveryResult{}, err
	}
	return provider.CreateOrganizationUnit(identitytransaction.WithExecutor(ctx, adapter.tx), request)
}

func (adapter moduleOrganizationUnitDelivery) ResolveOrganizationUnit(ctx context.Context, request organizationunit.ResolveRequest) (organizationunit.DeliveredOrganizationUnit, error) {
	provider, err := adapter.provider(ctx, request.AccessToken)
	if err != nil {
		return organizationunit.DeliveredOrganizationUnit{}, err
	}
	return provider.ResolveOrganizationUnit(identitytransaction.WithExecutor(ctx, adapter.tx), request)
}

func (adapter moduleOrganizationUnitDelivery) provider(ctx context.Context, accessToken string) (organizationunit.Delivery, error) {
	if adapter.binding == nil || adapter.binding.runtime == nil || adapter.binding.runtime.Auth == nil || adapter.binding.runtime.Binding == nil || adapter.tx == nil {
		return nil, &identitysdk.Error{Code: "identity.organization_unit_delivery_unavailable"}
	}
	claims, err := adapter.binding.runtime.Auth.VerifyAccessToken(ctx, strings.TrimSpace(accessToken))
	if err != nil {
		return nil, err
	}
	if claims.WorkspaceID != string(adapter.binding.application.WorkspaceID) || claims.Audience != string(adapter.binding.application.ApplicationKey) {
		return nil, &identitysdk.Error{Code: "identity.organization_unit_delivery_application_scope_mismatch"}
	}
	binding, ok := adapter.binding.runtime.Binding.(organizationunit.Binding)
	if !ok || binding.OrganizationUnitDelivery() == nil {
		return nil, &identitysdk.Error{Code: "identity.organization_unit_delivery_unavailable"}
	}
	return binding.OrganizationUnitDelivery(), nil
}

var _ organizationunit.Delivery = moduleOrganizationUnitDelivery{}
var _ organizationunit.UnitOfWorkBinder = moduleOrganizationUnitDeliveryBinder{}
var _ organizationunit.EmbeddedBinding = (*moduleBinding)(nil)
