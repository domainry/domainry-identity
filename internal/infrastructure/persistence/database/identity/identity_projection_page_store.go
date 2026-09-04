package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	projectionpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/projection"
	"github.com/domainry/domainry-orm/query"
)

func (s *SQLIdentityStore) SearchIdentityUsers(ctx context.Context, workspaceID string, queryValue identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
	return projectionpersistence.New(s).SearchIdentityUsers(ctx, workspaceID, queryValue)
}

func (s *SQLIdentityStore) SearchIdentityUsersWithinDataScope(ctx context.Context, workspaceID string, queryValue identitymodel.IdentityListQuery, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityUserPage, error) {
	return projectionpersistence.New(s).SearchIdentityUsersWithinDataScope(ctx, workspaceID, queryValue, scope)
}

func identityProjectionPredicates(queryValue identitymodel.IdentityListQuery, columns map[string]string) []query.Predicate {
	return projectionpersistence.Predicates(queryValue, columns)
}

func (s *SQLIdentityStore) identityProjectionPageSQL(ctx context.Context, workspaceID, table string, columns []string, queryValue identitymodel.IdentityListQuery, conditions []query.Predicate) (string, []any, error) {
	return projectionpersistence.New(s).PageSQL(ctx, workspaceID, table, columns, queryValue, conditions)
}

func sortedStringKeys(values map[string]any) []string {
	return projectionpersistence.SortedStringKeys(values)
}
