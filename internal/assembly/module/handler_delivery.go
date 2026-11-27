package moduleassembly

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityscope "github.com/domainry/domainry-identity-sdk/application"
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
		return identitysdk.HandlerDeliveryResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.handler_delivery_unavailable"}
	}
	var err error
	ctx, err = adapter.authorizedContext(ctx, request.AccessToken, request.WorkloadAuthority)
	if err != nil {
		return identitysdk.HandlerDeliveryResult{}, err
	}
	provider, ok := adapter.binding.runtime.Binding.(identitysdk.HandlerDeliveryBinding)
	if !ok || provider.HandlerDelivery() == nil {
		return identitysdk.HandlerDeliveryResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.handler_delivery_unavailable"}
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
		return nil, &identitysdk.Error{Class: identitysdk.ErrorClassInternal, Code: "identity.handler_delivery_transaction_required"}
	}
	return moduleHandlerDelivery{binding: binder.binding, tx: tx}, nil
}

func (adapter moduleHandlerDelivery) ResolveBoundIdentity(ctx context.Context, request identitysdk.HandlerBoundIdentityRequest) (identitysdk.HandlerBoundIdentity, error) {
	if adapter.binding == nil || adapter.binding.runtime == nil || adapter.binding.runtime.Auth == nil || adapter.binding.runtime.Binding == nil {
		return identitysdk.HandlerBoundIdentity{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.handler_delivery_unavailable"}
	}
	var err error
	ctx, err = adapter.authorizedContext(ctx, request.AccessToken, request.WorkloadAuthority)
	if err != nil {
		return identitysdk.HandlerBoundIdentity{}, err
	}
	provider, ok := adapter.binding.runtime.Binding.(identitysdk.HandlerDeliveryBinding)
	if !ok || provider.HandlerDelivery() == nil {
		return identitysdk.HandlerBoundIdentity{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.handler_delivery_unavailable"}
	}
	if adapter.tx != nil {
		ctx = identitytransaction.WithExecutor(ctx, adapter.tx)
	}
	return provider.HandlerDelivery().ResolveBoundIdentity(ctx, request)
}

func (adapter moduleHandlerDelivery) authorizedContext(ctx context.Context, accessToken string, workload *identitysdk.HandlerWorkloadAuthority) (context.Context, error) {
	accessToken = strings.TrimSpace(accessToken)
	if (accessToken != "") == (workload != nil) {
		return ctx, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.handler_delivery_authority_invalid"}
	}
	if workload == nil {
		claims, err := adapter.binding.runtime.Auth.VerifyAccessToken(ctx, accessToken)
		if err != nil {
			return ctx, err
		}
		if !adapter.binding.acceptsWorkspace(ctx, claims.WorkspaceID) || claims.Audience != string(adapter.binding.application.ApplicationKey) {
			return ctx, &identitysdk.Error{Class: identitysdk.ErrorClassForbidden, Code: "identity.handler_delivery_application_scope_mismatch"}
		}
		return ctx, nil
	}
	workspaceID := strings.TrimSpace(string(workload.WorkspaceID))
	if !workload.WorkspaceID.Valid() || !adapter.binding.application.ApplicationKey.Valid() || !adapter.binding.acceptsWorkspace(ctx, workspaceID) {
		return ctx, &identitysdk.Error{Class: identitysdk.ErrorClassForbidden, Code: "identity.handler_delivery_application_scope_mismatch"}
	}
	ctx = requestcontext.WithWorkspaceID(ctx, workspaceID)
	return identityscope.WithScope(ctx, identitysdk.ApplicationScope{WorkspaceID: workload.WorkspaceID, ApplicationKey: adapter.binding.application.ApplicationKey}), nil
}

var _ identitysdk.HandlerDelivery = moduleHandlerDelivery{}
var _ identitysdk.HandlerDeliveryUnitOfWorkBinder = moduleHandlerDeliveryBinder{}
var _ identitysdk.EmbeddedHandlerDeliveryBinding = (*moduleBinding)(nil)
