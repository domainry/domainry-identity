package moduleassembly

import (
	"context"
	identitysdk "github.com/domainry/domainry-identity-sdk"
)

func (binding *moduleBinding) acceptsWorkspace(ctx context.Context, workspaceID string) bool {
	if binding.runtime.WorkspaceResolver == nil {
		return workspaceID == string(binding.application.WorkspaceID)
	}
	resolved, err := binding.runtime.WorkspaceResolver.ResolveWorkspace(ctx, identitysdk.WorkspaceID(workspaceID))
	return err == nil && string(resolved) == workspaceID
}
