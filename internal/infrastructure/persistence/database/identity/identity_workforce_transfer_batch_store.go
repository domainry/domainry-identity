package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	transferbatchpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/workforce/transferbatch"
)

func (s *SQLIdentityStore) workforceTransferBatchStore() transferbatchpersistence.Store {
	return transferbatchpersistence.New(s, nowString, s.applyIdentityWorkforceLifecycleTx)
}

func (s *SQLIdentityStore) GetIdentityWorkforceTransferBatchReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityWorkforceTransferBatchReceipt, bool, error) {
	return s.workforceTransferBatchStore().GetReceipt(ctx, workspaceID, idempotencyKey)
}

func (s *SQLIdentityStore) ApplyIdentityWorkforceTransferBatch(ctx context.Context, mutation identitymodel.IdentityWorkforceTransferBatchMutation) (identitymodel.IdentityWorkforceTransferBatchReceipt, error) {
	return s.workforceTransferBatchStore().Apply(ctx, mutation)
}
