package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	entitlementpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/entitlement"
	roleassignmentpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/roleassignment"
)

const identityUserRoleAssignmentInsertBatchSize = entitlementpersistence.AssignmentInsertBatchSize

func (s *SQLIdentityStore) entitlementStore() entitlementpersistence.Store {
	return entitlementpersistence.New(s, nowString, func(ctx context.Context, execer entitlementpersistence.Execer, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
		return roleassignmentpersistence.New(s, nowString).UpsertWithExecutorWithinDataScope(ctx, execer, workspaceID, assignment, scope)
	})
}

func (s *SQLIdentityStore) GetIdentityEntitlementBatchReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	return s.entitlementStore().GetReceipt(ctx, workspaceID, idempotencyKey)
}

func (s *SQLIdentityStore) GetIdentityEntitlementBatchReceiptWithinDataScope(ctx context.Context, workspaceID, idempotencyKey string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	return s.entitlementStore().GetReceiptWithinDataScope(ctx, workspaceID, idempotencyKey, scope)
}

func (s *SQLIdentityStore) ApplyIdentityEntitlementBatch(ctx context.Context, mutation identitymodel.IdentityEntitlementBatchMutation) (identitymodel.IdentityEntitlementBatchReceipt, error) {
	return s.entitlementStore().Apply(ctx, mutation)
}

func (s *SQLIdentityStore) ApplyIdentityEntitlementBatchWithinDataScope(ctx context.Context, mutation identitymodel.IdentityEntitlementBatchMutation, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	return s.entitlementStore().ApplyWithinDataScope(ctx, mutation, scope)
}
