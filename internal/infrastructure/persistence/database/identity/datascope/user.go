package datascope

import (
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-orm/query"
)

// UserPredicate maps the public Identity data-scope contract to the user's
// natural ownership columns: owner -> id and org scopes -> org_id.
func UserPredicate(scope identitymodel.IdentityDataScopeFilter, id, orgID query.Expression) query.Predicate {
	scope = scope.Normalized()
	if scope.Unrestricted {
		return query.AlwaysTrue()
	}
	predicates := make([]query.Predicate, 0, 2)
	if values := scopeValues(scope.OwnerUserIDs); len(values) > 0 {
		predicates = append(predicates, query.InExpression(id, values...))
	}
	if values := scopeValues(scope.OwnerOrgIDs); len(values) > 0 {
		predicates = append(predicates, query.InExpression(orgID, values...))
	}
	if len(predicates) == 0 {
		return query.AlwaysFalse()
	}
	return query.Or(predicates...)
}

// UserExists correlates a relation's user id to a persisted Identity user in
// the same workspace and applies the compiled scope inside the subquery.
func UserExists(workspaceID string, outerUserID query.Expression, scope identitymodel.IdentityDataScopeFilter) query.Predicate {
	return query.Exists("_identity_users", query.And(
		query.Equal("workspace_id", strings.TrimSpace(workspaceID)),
		query.EqualExpressions(query.Column("id"), outerUserID),
		UserPredicate(scope, query.Column("id"), query.Column("org_id")),
	))
}

func scopeValues(values []string) []any {
	result := make([]any, len(values))
	for index := range values {
		result[index] = values[index]
	}
	return result
}
