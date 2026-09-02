package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	directorypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/directory"
	"github.com/domainry/domainry-orm/query"
)

func (s *SQLIdentityStore) SearchIdentityUsers(ctx context.Context, workspaceID string, queryValue identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
	return directorypersistence.New(s).SearchIdentityUsers(ctx, workspaceID, queryValue)
}

func identityDirectoryPredicates(queryValue identitymodel.IdentityListQuery, columns map[string]string) []query.Predicate {
	return directorypersistence.Predicates(queryValue, columns)
}

func (s *SQLIdentityStore) identityDirectoryPageSQL(ctx context.Context, workspaceID, table string, columns []string, queryValue identitymodel.IdentityListQuery, conditions []query.Predicate) (string, []any, error) {
	return directorypersistence.New(s).PageSQL(ctx, workspaceID, table, columns, queryValue, conditions)
}

func sortedStringKeys(values map[string]any) []string {
	return directorypersistence.SortedStringKeys(values)
}
