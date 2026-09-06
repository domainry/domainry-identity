package moduleassembly

import (
	"context"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
)

type moduleHandlerDelivery struct {
	binding *moduleBinding
	tx      identitytransaction.Executor
}

type moduleHandlerDeliveryBinder struct {
	binding *moduleBinding
}

func (binding *moduleBinding) HandlerDeliveryUnitOfWorkBinder() identitysdk.HandlerDeliveryUnitOfWorkBinder {
	return moduleHandlerDeliveryBinder{binding: binding}
}

func (adapter moduleHandlerDelivery) DeliverIdentity(ctx context.Context, request identitysdk.HandlerDeliveryRequest) (identitysdk.HandlerDeliveryResult, error) {
	if adapter.binding == nil || adapter.binding.runtime == nil || adapter.binding.runtime.Auth == nil || adapter.binding.runtime.Binding == nil {
		return identitysdk.HandlerDeliveryResult{}, &identitysdk.Error{Code: "identity.handler_delivery_unavailable"}
	}
	claims, err := adapter.binding.runtime.Auth.VerifyAccessToken(ctx, strings.TrimSpace(request.AccessToken))
	if err != nil {
		return identitysdk.HandlerDeliveryResult{}, err
	}
	if claims.WorkspaceID != string(adapter.binding.application.WorkspaceID) || claims.Audience != string(adapter.binding.application.ApplicationKey) {
		return identitysdk.HandlerDeliveryResult{}, &identitysdk.Error{Code: "identity.handler_delivery_application_scope_mismatch"}
	}
	provider, ok := adapter.binding.runtime.Binding.(identitysdk.HandlerDeliveryBinding)
	if !ok || provider.HandlerDelivery() == nil {
		return identitysdk.HandlerDeliveryResult{}, &identitysdk.Error{Code: "identity.handler_delivery_unavailable"}
	}
	if adapter.tx != nil {
		ctx = identitytransaction.WithExecutor(ctx, adapter.tx)
	}
	if request.ProfileBinding != nil && len(request.ProfileBinding.EmbeddedProfileRecord) != 0 {
		ctx = identityapplication.WithEmbeddedHandlerProfileRecord(ctx, request.ProfileBinding.ObjectKey, request.ProfileBinding.ProfileID, request.ProfileBinding.EmbeddedProfileRecord)
	}
	return provider.HandlerDelivery().DeliverIdentity(ctx, request)
}

func (binder moduleHandlerDeliveryBinder) BindHandlerDeliveryUnitOfWork(transaction identitysdk.EmbeddedTransaction) (identitysdk.HandlerDelivery, error) {
	tx, ok := embeddedTransactionExecutor(transaction)
	if !ok {
		return nil, &identitysdk.Error{Code: "identity.handler_delivery_transaction_required"}
	}
	return moduleHandlerDelivery{binding: binder.binding, tx: tx}, nil
}

func (adapter moduleHandlerDelivery) ResolveBoundIdentity(ctx context.Context, request identitysdk.HandlerBoundIdentityRequest) (identitysdk.HandlerBoundIdentity, error) {
	if adapter.binding == nil || adapter.binding.runtime == nil || adapter.binding.runtime.Auth == nil || adapter.binding.runtime.Binding == nil {
		return identitysdk.HandlerBoundIdentity{}, &identitysdk.Error{Code: "identity.handler_delivery_unavailable"}
	}
	claims, err := adapter.binding.runtime.Auth.VerifyAccessToken(ctx, strings.TrimSpace(request.AccessToken))
	if err != nil {
		return identitysdk.HandlerBoundIdentity{}, err
	}
	if claims.WorkspaceID != string(adapter.binding.application.WorkspaceID) || claims.Audience != string(adapter.binding.application.ApplicationKey) {
		return identitysdk.HandlerBoundIdentity{}, &identitysdk.Error{Code: "identity.handler_delivery_application_scope_mismatch"}
	}
	provider, ok := adapter.binding.runtime.Binding.(identitysdk.HandlerDeliveryBinding)
	if !ok || provider.HandlerDelivery() == nil {
		return identitysdk.HandlerBoundIdentity{}, &identitysdk.Error{Code: "identity.handler_delivery_unavailable"}
	}
	if adapter.tx != nil {
		ctx = identitytransaction.WithExecutor(ctx, adapter.tx)
	}
	return provider.HandlerDelivery().ResolveBoundIdentity(ctx, request)
}

var _ identitysdk.HandlerDelivery = moduleHandlerDelivery{}
var _ identitysdk.HandlerDeliveryUnitOfWorkBinder = moduleHandlerDeliveryBinder{}
var _ identitysdk.EmbeddedHandlerDeliveryBinding = (*moduleBinding)(nil)
