package identitysdkadapter

import (
	"context"
	"net/http"
	"strings"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

// IdentityMutationFence is the application-boundary cutover guard. It is
// checked by both the in-process Module Binding and the standalone service;
// migration operations deliberately use their dedicated repository instead.
type OperationsPersistence interface {
	BindOperationsPersistence()
	OperationsPersistenceBound() bool
}

type IdentityMutationFence interface {
	OperationsPersistence
	IdentityWritesFrozen(context.Context, string) (bool, error)
}

// FederatedLoginTransactionReader resolves the workspace hidden behind opaque
// OIDC/SAML state without consuming the one-time transaction. This keeps a
// single-tenant cutover from blocking callbacks for unrelated SaaS tenants.
type FederatedLoginTransactionReader interface {
	FederatedLoginWorkspace(context.Context, string, string, time.Time) (string, bool, error)
}

func (binding *sdkBinding) requireMutableWorkspace(ctx context.Context, workspaceID identitysdk.WorkspaceID) error {
	workspace := strings.TrimSpace(string(workspaceID))
	if !identitysdk.WorkspaceID(workspace).Valid() {
		return &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "backend.workspace_scope_required"}
	}
	if binding.workspaceResolver != nil {
		resolved, err := binding.workspaceResolver.ResolveWorkspace(ctx, workspaceID)
		if err != nil || resolved != workspaceID {
			return &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "auth.invalid_credentials"}
		}
	}
	frozen, err := binding.mutationFence.IdentityWritesFrozen(ctx, workspace)
	if err != nil {
		return &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.write_fence_unavailable", Cause: err}
	}
	if frozen {
		return &identitysdk.Error{StatusCode: http.StatusLocked, Code: "identity.workspace_writes_frozen"}
	}
	return nil
}

func (binding *sdkBinding) federatedLoginWorkspace(ctx context.Context, provider, state string) (identitysdk.WorkspaceID, error) {
	workspaceID, found, err := binding.loginTransactions.FederatedLoginWorkspace(ctx, provider, state, binding.clock.Now().UTC())
	if err != nil {
		return "", &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.login_transaction_unavailable", Cause: err}
	}
	workspace := identitysdk.WorkspaceID(strings.TrimSpace(workspaceID))
	if !found || !workspace.Valid() {
		return "", &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "auth.provider_state_invalid"}
	}
	return workspace, nil
}
