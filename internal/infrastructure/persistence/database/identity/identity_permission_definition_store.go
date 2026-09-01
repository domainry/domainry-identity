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

func (store *SQLIdentityStore) ReconcileIdentityPermissionDefinitions(ctx context.Context, request identitymodel.IdentityPermissionReconcileRequest) (identitymodel.IdentityPermissionReconcileReceipt, error) {
	return store.permissionDefinitionStore().Reconcile(ctx, request)
}
