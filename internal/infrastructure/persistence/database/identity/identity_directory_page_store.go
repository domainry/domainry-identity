package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	directorypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/directory"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

// Directory is a separate persistence owner. SQLIdentityStore retains the
// repository facade required by the domain port, but no longer owns directory
// query construction.
func (s *SQLIdentityStore) SearchIdentityUsers(ctx context.Context, workspaceID string, query identitymodel.IdentityListQuery) (identitymodel.IdentityUserPage, error) {
	return directorypersistence.New(s).SearchIdentityUsers(ctx, workspaceID, query)
}

func (s *SQLIdentityStore) SearchIdentityWorkforceProfiles(ctx context.Context, workspaceID string, query identitymodel.IdentityListQuery) (identitymodel.IdentityWorkforceProfilePage, error) {
	return directorypersistence.New(s).SearchIdentityWorkforceProfiles(ctx, workspaceID, query)
}

// The following package-private seams keep focused SQL failure tests close to
// the facade while exercising the extracted owner implementation.
func identityDirectoryPredicates(query identitymodel.IdentityListQuery, columns map[string]string) []ormbuilder.Predicate {
	return directorypersistence.Predicates(query, columns)
}

func (s *SQLIdentityStore) identityDirectoryPageSQL(ctx context.Context, workspaceID, table string, columns []string, query identitymodel.IdentityListQuery, conditions []ormbuilder.Predicate) (string, []any, error) {
	return directorypersistence.New(s).PageSQL(ctx, workspaceID, table, columns, query, conditions)
}

func sortedStringKeys(values map[string]any) []string {
	return directorypersistence.SortedStringKeys(values)
}
