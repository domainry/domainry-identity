package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	projectionpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/projection"
)

const identityProjectionBatchMaxItems = projectionpersistence.BatchMaxItems

func (s *SQLIdentityStore) ListIdentityUserProjectionFacts(ctx context.Context, workspaceID string, userIDs []string) (identitymodel.IdentityUserProjectionFacts, error) {
	return projectionpersistence.New(s).ListUserFacts(ctx, workspaceID, userIDs)
}
