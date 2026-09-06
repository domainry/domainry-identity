package identity

import (
	"context"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-orm/query"
)

// CountIdentityWorkspaceUsage executes exactly one bounded GROUP BY query for
// the trusted catalog page. The application merges zero-account Workspaces;
// persistence never loads user rows or person-identifying columns.
func (s *SQLIdentityStore) CountIdentityWorkspaceUsage(ctx context.Context, workspaceIDs []string) ([]identitymodel.IdentityWorkspaceUsageGroup, error) {
	if len(workspaceIDs) == 0 {
		return []identitymodel.IdentityWorkspaceUsageGroup{}, nil
	}
	values, err := identityWorkspaceUsageScopeValues(workspaceIDs)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := query.NewSelectBuilder(s.sqlRenderer(), "_identity_users").
		Projections(
			query.Project(query.Column("workspace_id")),
			query.Project(query.Column("account_type")),
			query.Project(query.Column("status")),
			query.Project(query.CountAll()),
		).
		Where(query.In("workspace_id", values...)).
		GroupBy(query.Column("workspace_id"), query.Column("account_type"), query.Column("status")).
		OrderBy(
			query.Ascending("workspace_id"),
			query.Ascending("account_type"),
			query.Ascending("status"),
		).
		Build()
	if err != nil {
		return nil, fmt.Errorf("build Identity Workspace usage aggregate query: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := make([]identitymodel.IdentityWorkspaceUsageGroup, 0)
	for rows.Next() {
		var group identitymodel.IdentityWorkspaceUsageGroup
		if err := rows.Scan(&group.WorkspaceID, &group.AccountType, &group.Status, &group.Count); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}

// CountIdentityWorkspaceActiveHumanAccountsWithActiveRole executes one
// additional bounded aggregate query. The inner ORM query de-duplicates active
// human user IDs that have at least one active role assignment; only the outer
// Workspace/count scalars cross the persistence boundary.
func (s *SQLIdentityStore) CountIdentityWorkspaceActiveHumanAccountsWithActiveRole(ctx context.Context, workspaceIDs []string) ([]identitymodel.IdentityWorkspaceActiveHumanRoleCount, error) {
	if len(workspaceIDs) == 0 {
		return []identitymodel.IdentityWorkspaceActiveHumanRoleCount{}, nil
	}
	values, err := identityWorkspaceUsageScopeValues(workspaceIDs)
	if err != nil {
		return nil, err
	}
	distinctUsers := query.NewSelectBuilder(s.sqlRenderer(), "_identity_users").Alias("usage_user").
		Distinct().
		Projections(
			query.Project(query.QualifiedColumn("usage_user", "workspace_id")),
			query.Project(query.QualifiedColumn("usage_user", "id")),
		).
		Join(query.InnerJoin("_identity_user_role_assignments", "usage_assignment", query.And(
			query.EqualExpressions(query.QualifiedColumn("usage_user", "workspace_id"), query.QualifiedColumn("usage_assignment", "workspace_id")),
			query.EqualExpressions(query.QualifiedColumn("usage_user", "id"), query.QualifiedColumn("usage_assignment", "user_id")),
		))).
		Where(query.And(
			query.InExpression(query.QualifiedColumn("usage_user", "workspace_id"), values...),
			query.EqualValue(query.QualifiedColumn("usage_user", "account_type"), string(identitymodel.IdentityAccountHuman)),
			query.EqualValue(query.QualifiedColumn("usage_user", "status"), string(identitymodel.IdentityStatusActive)),
			query.EqualValue(query.QualifiedColumn("usage_assignment", "status"), "active"),
		))
	statement, arguments, err := query.NewSelectFromSubquery(s.sqlRenderer(), distinctUsers, "eligible_usage_user").
		Projections(
			query.Project(query.QualifiedColumn("eligible_usage_user", "workspace_id")),
			query.Project(query.CountAll()),
		).
		GroupBy(query.QualifiedColumn("eligible_usage_user", "workspace_id")).
		OrderBy(query.Ascending("workspace_id")).
		Build()
	if err != nil {
		return nil, fmt.Errorf("build active human Identity Workspace role usage aggregate query: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make([]identitymodel.IdentityWorkspaceActiveHumanRoleCount, 0)
	for rows.Next() {
		var count identitymodel.IdentityWorkspaceActiveHumanRoleCount
		if err := rows.Scan(&count.WorkspaceID, &count.Count); err != nil {
			return nil, err
		}
		counts = append(counts, count)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

func identityWorkspaceUsageScopeValues(workspaceIDs []string) ([]any, error) {
	if len(workspaceIDs) > 100 {
		return nil, identityWorkspaceUsageStoreError(apperror.KindBadRequest, "backend.identity.workspace_usage_page_size_invalid")
	}
	values := make([]any, len(workspaceIDs))
	seen := make(map[string]struct{}, len(workspaceIDs))
	for index, value := range workspaceIDs {
		workspaceID := strings.TrimSpace(value)
		if workspaceID == "" || workspaceID != value {
			return nil, identityWorkspaceUsageStoreError(apperror.KindBadRequest, "backend.identity.workspace_usage_catalog_scope_invalid")
		}
		if _, err := identitymodel.NewWorkspaceID(workspaceID); err != nil {
			return nil, identityWorkspaceUsageStoreError(apperror.KindBadRequest, "backend.identity.workspace_usage_catalog_scope_invalid")
		}
		if _, duplicate := seen[workspaceID]; duplicate {
			return nil, identityWorkspaceUsageStoreError(apperror.KindBadRequest, "backend.identity.workspace_usage_catalog_scope_invalid")
		}
		seen[workspaceID] = struct{}{}
		values[index] = workspaceID
	}
	return values, nil
}

func identityWorkspaceUsageStoreError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}
