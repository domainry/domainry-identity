package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	directorypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/directory"
)

const identityDirectoryBatchMaxItems = directorypersistence.BatchMaxItems

func (s *SQLIdentityStore) ListIdentityUserDirectoryFacts(ctx context.Context, workspaceID string, userIDs []string) (identitymodel.IdentityUserDirectoryFacts, error) {
	return directorypersistence.New(s).ListUserFacts(ctx, workspaceID, userIDs)
}
