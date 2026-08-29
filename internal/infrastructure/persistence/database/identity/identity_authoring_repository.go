package identity

import authoringpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/authoring"

type IdentityAuthoringRepository = authoringpersistence.Repository

func NewIdentityAuthoringRepository(store *SQLIdentityStore) *IdentityAuthoringRepository {
	return authoringpersistence.NewRepository(store)
}
