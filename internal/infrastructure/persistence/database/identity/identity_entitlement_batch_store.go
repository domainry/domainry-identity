package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	entitlementpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/entitlement"
)

const identityUserRoleAssignmentInsertBatchSize = entitlementpersistence.AssignmentInsertBatchSize

func (s *SQLIdentityStore) GetIdentityEntitlementBatchReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	return entitlementpersistence.New(s, nowString).GetReceipt(ctx, workspaceID, idempotencyKey)
}

func (s *SQLIdentityStore) ApplyIdentityEntitlementBatch(ctx context.Context, mutation identitymodel.IdentityEntitlementBatchMutation) (identitymodel.IdentityEntitlementBatchReceipt, error) {
	return entitlementpersistence.New(s, nowString).Apply(ctx, mutation)
}
