package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	permissionpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/authorization/permission"
)

func (store *SQLIdentityStore) permissionDefinitionStore() *permissionpersistence.Store {
	return permissionpersistence.New(store, nowString)
}

func (store *SQLIdentityStore) ListIdentityPermissionDefinitions(ctx context.Context, workspaceID string) ([]identitymodel.IdentityPermissionDefinitionRecord, error) {
	return store.permissionDefinitionStore().List(ctx, workspaceID)
}

func (store *SQLIdentityStore) GetIdentityPermissionDefinition(ctx context.Context, workspaceID, permissionKey string) (identitymodel.IdentityPermissionDefinitionRecord, bool, error) {
	return store.permissionDefinitionStore().Get(ctx, workspaceID, permissionKey)
}

func (store *SQLIdentityStore) SetIdentityPermissionDefinitionEnabled(ctx context.Context, workspaceID, permissionKey string, enabled bool) (bool, error) {
	return store.permissionDefinitionStore().SetEnabled(ctx, workspaceID, permissionKey, enabled)
}

func (store *SQLIdentityStore) ReconcileIdentityPermissionDefinitions(ctx context.Context, request identitymodel.IdentityPermissionReconcileRequest) (identitymodel.IdentityPermissionReconcileReceipt, error) {
	return store.permissionDefinitionStore().Reconcile(ctx, request)
}
