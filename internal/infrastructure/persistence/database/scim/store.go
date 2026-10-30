package scimpersistence

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/mutation"
	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
	identityfailure "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/failure"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	QueryIdentityContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryIdentityRowContext(context.Context, string, ...any) *sql.Row
}

type Store struct {
	backend Backend
	now     func() time.Time
}

func NewStore(backend Backend) *Store {
	return &Store{backend: backend, now: func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }}
}

func (s *Store) ListUserLinks(ctx context.Context, workspaceID string) ([]scimmodel.UserLink, error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_scim_users", strings.TrimSpace(workspaceID)).
		Columns("user_id", "external_id", "user_name", "department", "version", "created_at", "updated_at", "deleted_at").
		Where(query.Equal("deleted_at", int64(0))).OrderBy(query.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build SCIM user list: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	links := []scimmodel.UserLink{}
	for rows.Next() {
		link, scanErr := scanUserLink(rows, workspaceID)
		if scanErr != nil {
			return nil, scanErr
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

func (s *Store) GetUserLink(ctx context.Context, workspaceID, userID string) (scimmodel.UserLink, bool, error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_scim_users", strings.TrimSpace(workspaceID)).
		Columns("user_id", "external_id", "user_name", "department", "version", "created_at", "updated_at", "deleted_at").
		Where(query.And(query.Equal("user_id", strings.TrimSpace(userID)), query.Equal("deleted_at", int64(0)))).Limit(1).Build()
	if err != nil {
		return scimmodel.UserLink{}, false, fmt.Errorf("build SCIM user query: %w", err)
	}
	link, err := scanUserLink(s.backend.QueryIdentityRowContext(ctx, statement, arguments...), workspaceID)
	if errors.Is(err, sql.ErrNoRows) {
		return scimmodel.UserLink{}, false, nil
	}
	return link, err == nil, err
}

func (s *Store) GetDeletedUserLinkByUserName(ctx context.Context, workspaceID, userName string) (scimmodel.UserLink, bool, error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_scim_users", strings.TrimSpace(workspaceID)).
		Columns("user_id", "external_id", "user_name", "department", "version", "created_at", "updated_at", "deleted_at").
		Where(query.And(query.Equal("user_name_key", normalizedKey(userName)), query.GreaterThan("deleted_at", int64(0)))).Limit(1).Build()
	if err != nil {
		return scimmodel.UserLink{}, false, fmt.Errorf("build deleted SCIM user query: %w", err)
	}
	link, err := scanUserLink(s.backend.QueryIdentityRowContext(ctx, statement, arguments...), workspaceID)
	if errors.Is(err, sql.ErrNoRows) {
		return scimmodel.UserLink{}, false, nil
	}
	return link, err == nil, err
}

type rowScanner interface{ Scan(...any) error }

func scanUserLink(scanner rowScanner, workspaceID string) (scimmodel.UserLink, error) {
	var link scimmodel.UserLink
	var externalID sql.NullString
	var createdAt, updatedAt, deletedAt int64
	err := scanner.Scan(&link.UserID, &externalID, &link.UserName, &link.Department, &link.Version, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return scimmodel.UserLink{}, err
	}
	link.WorkspaceID = strings.TrimSpace(workspaceID)
	link.ExternalID = identitypersistence.ValueFromNull(externalID)
	link.CreatedAt, link.UpdatedAt = timevalue.String(createdAt), timevalue.String(updatedAt)
	if deletedAt > 0 {
		link.DeletedAt = timevalue.String(deletedAt)
	}
	return link, nil
}

func (s *Store) CreateUserLink(ctx context.Context, link scimmodel.UserLink) error {
	now := s.now().UnixMilli()
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_scim_users", strings.TrimSpace(link.WorkspaceID)).
		Columns("user_id", "external_id", "user_name", "user_name_key", "department", "version", "created_at", "updated_at", "deleted_at").
		Values(strings.TrimSpace(link.UserID), nullable(link.ExternalID), strings.TrimSpace(link.UserName), normalizedKey(link.UserName), strings.TrimSpace(link.Department), int64(1), now, now, int64(0)).Build()
	if err != nil {
		return fmt.Errorf("build SCIM user link create: %w", err)
	}
	_, err = s.execer(ctx).ExecContext(ctx, statement, arguments...)
	return identityfailure.ConstraintError(err, "scim_user", strings.TrimSpace(link.UserID), mutation.MutationConflictUnique)
}

func (s *Store) RestoreUserLink(ctx context.Context, link scimmodel.UserLink, expectedVersion int64) (bool, error) {
	now := s.now().UnixMilli()
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_scim_users", strings.TrimSpace(link.WorkspaceID)).
		Set("external_id", nullable(link.ExternalID)).Set("user_name", strings.TrimSpace(link.UserName)).Set("user_name_key", normalizedKey(link.UserName)).
		Set("department", strings.TrimSpace(link.Department)).
		Set("version", expectedVersion+1).Set("updated_at", now).Set("deleted_at", int64(0)).
		Where(query.And(query.Equal("user_id", strings.TrimSpace(link.UserID)), query.Equal("version", expectedVersion), query.GreaterThan("deleted_at", int64(0)))).Build()
	if err != nil {
		return false, fmt.Errorf("build SCIM user link restore: %w", err)
	}
	result, err := s.execer(ctx).ExecContext(ctx, statement, arguments...)
	err = identityfailure.ConstraintError(err, "scim_user", strings.TrimSpace(link.UserID), mutation.MutationConflictUnique)
	return exactlyOne(result, err)
}

func (s *Store) UpdateUserLink(ctx context.Context, link scimmodel.UserLink, expectedVersion int64) (bool, error) {
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_scim_users", strings.TrimSpace(link.WorkspaceID)).
		Set("external_id", nullable(link.ExternalID)).Set("user_name", strings.TrimSpace(link.UserName)).Set("user_name_key", normalizedKey(link.UserName)).Set("department", strings.TrimSpace(link.Department)).
		Set("version", expectedVersion+1).Set("updated_at", s.now().UnixMilli()).
		Where(query.And(query.Equal("user_id", strings.TrimSpace(link.UserID)), query.Equal("version", expectedVersion), query.Equal("deleted_at", int64(0)))).Build()
	if err != nil {
		return false, fmt.Errorf("build SCIM user link update: %w", err)
	}
	result, err := s.execer(ctx).ExecContext(ctx, statement, arguments...)
	err = identityfailure.ConstraintError(err, "scim_user", strings.TrimSpace(link.UserID), mutation.MutationConflictUnique)
	return exactlyOne(result, err)
}

func (s *Store) DeleteUserLink(ctx context.Context, workspaceID, userID string, expectedVersion int64) (bool, error) {
	deleted := false
	err := s.withinTransaction(ctx, func(executor identitytransaction.Executor) error {
		var operationErr error
		deleted, operationErr = s.deleteUserLink(ctx, executor, workspaceID, userID, expectedVersion)
		return operationErr
	})
	return deleted, err
}

func (s *Store) deleteUserLink(ctx context.Context, executor identitytransaction.Executor, workspaceID, userID string, expectedVersion int64) (bool, error) {
	now := s.now().UnixMilli()
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_scim_users", strings.TrimSpace(workspaceID)).
		Set("version", expectedVersion+1).Set("updated_at", now).Set("deleted_at", now).
		Where(query.And(query.Equal("user_id", strings.TrimSpace(userID)), query.Equal("version", expectedVersion), query.Equal("deleted_at", int64(0)))).Build()
	if err != nil {
		return false, fmt.Errorf("build SCIM user link delete: %w", err)
	}
	result, err := executor.ExecContext(ctx, statement, arguments...)
	deleted, err := exactlyOne(result, err)
	if err != nil || !deleted {
		return deleted, err
	}
	statement, arguments, err = query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_scim_group_members", strings.TrimSpace(workspaceID)).
		Columns("group_id").Where(query.Equal("user_id", strings.TrimSpace(userID))).Build()
	if err != nil {
		return false, fmt.Errorf("build SCIM user membership group query: %w", err)
	}
	rows, err := executor.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	groupIDs := []string{}
	for rows.Next() {
		var groupID string
		if err := rows.Scan(&groupID); err != nil {
			_ = rows.Close()
			return false, err
		}
		groupIDs = append(groupIDs, groupID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	statement, arguments, err = query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_scim_group_members", strings.TrimSpace(workspaceID)).
		Where(query.Equal("user_id", strings.TrimSpace(userID))).Build()
	if err != nil {
		return false, fmt.Errorf("build SCIM user membership delete: %w", err)
	}
	if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
		return false, err
	}
	for _, groupID := range groupIDs {
		statement, arguments, err = query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_scim_groups", strings.TrimSpace(workspaceID)).
			SetExpression("version", query.Add(query.Column("version"), query.Value(int64(1)))).Set("updated_at", now).
			Where(query.And(query.Equal("group_id", groupID), query.Equal("deleted_at", int64(0)))).Build()
		if err != nil {
			return false, fmt.Errorf("build SCIM group version update: %w", err)
		}
		if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (s *Store) ListGroups(ctx context.Context, workspaceID string) ([]scimmodel.DirectoryGroup, error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_scim_groups", strings.TrimSpace(workspaceID)).
		Columns("group_id", "external_id", "display_name", "version", "created_at", "updated_at", "deleted_at").
		Where(query.Equal("deleted_at", int64(0))).OrderBy(query.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build SCIM group list: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	groups := []scimmodel.DirectoryGroup{}
	for rows.Next() {
		group, scanErr := scanGroup(rows, workspaceID)
		if scanErr != nil {
			_ = rows.Close()
			return nil, scanErr
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range groups {
		members, memberErr := s.listGroupMembers(ctx, workspaceID, groups[index].GroupID)
		if memberErr != nil {
			return nil, memberErr
		}
		groups[index].MemberIDs = members
	}
	return groups, nil
}

func (s *Store) GetGroup(ctx context.Context, workspaceID, groupID string) (scimmodel.DirectoryGroup, bool, error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_scim_groups", strings.TrimSpace(workspaceID)).
		Columns("group_id", "external_id", "display_name", "version", "created_at", "updated_at", "deleted_at").
		Where(query.And(query.Equal("group_id", strings.TrimSpace(groupID)), query.Equal("deleted_at", int64(0)))).Limit(1).Build()
	if err != nil {
		return scimmodel.DirectoryGroup{}, false, fmt.Errorf("build SCIM group query: %w", err)
	}
	group, err := scanGroup(s.backend.QueryIdentityRowContext(ctx, statement, arguments...), workspaceID)
	if errors.Is(err, sql.ErrNoRows) {
		return scimmodel.DirectoryGroup{}, false, nil
	}
	if err != nil {
		return scimmodel.DirectoryGroup{}, false, err
	}
	group.MemberIDs, err = s.listGroupMembers(ctx, workspaceID, groupID)
	return group, err == nil, err
}

func scanGroup(scanner rowScanner, workspaceID string) (scimmodel.DirectoryGroup, error) {
	var group scimmodel.DirectoryGroup
	var externalID sql.NullString
	var createdAt, updatedAt, deletedAt int64
	err := scanner.Scan(&group.GroupID, &externalID, &group.DisplayName, &group.Version, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		return scimmodel.DirectoryGroup{}, err
	}
	group.WorkspaceID = strings.TrimSpace(workspaceID)
	group.ExternalID = identitypersistence.ValueFromNull(externalID)
	group.CreatedAt, group.UpdatedAt = timevalue.String(createdAt), timevalue.String(updatedAt)
	if deletedAt > 0 {
		group.DeletedAt = timevalue.String(deletedAt)
	}
	return group, nil
}

func (s *Store) listGroupMembers(ctx context.Context, workspaceID, groupID string) ([]string, error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_scim_group_members", strings.TrimSpace(workspaceID)).
		Columns("user_id").Where(query.Equal("group_id", strings.TrimSpace(groupID))).OrderBy(query.Ascending("user_id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build SCIM group member list: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := []string{}
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		members = append(members, userID)
	}
	return members, rows.Err()
}

func (s *Store) CreateGroup(ctx context.Context, group scimmodel.DirectoryGroup) error {
	return s.withinTransaction(ctx, func(executor identitytransaction.Executor) error {
		return s.createGroup(ctx, executor, group)
	})
}

func (s *Store) createGroup(ctx context.Context, executor identitytransaction.Executor, group scimmodel.DirectoryGroup) error {
	now := s.now().UnixMilli()
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_scim_groups", strings.TrimSpace(group.WorkspaceID)).
		Columns("group_id", "external_id", "display_name", "version", "created_at", "updated_at", "deleted_at").
		Values(strings.TrimSpace(group.GroupID), nullable(group.ExternalID), strings.TrimSpace(group.DisplayName), int64(1), now, now, int64(0)).Build()
	if err != nil {
		return fmt.Errorf("build SCIM group create: %w", err)
	}
	if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
		return identityfailure.ConstraintError(err, "scim_group", strings.TrimSpace(group.GroupID), mutation.MutationConflictUnique)
	}
	if err := s.replaceGroupMembers(ctx, executor, group.WorkspaceID, group.GroupID, group.MemberIDs, now); err != nil {
		return err
	}
	return nil
}

func (s *Store) UpdateGroup(ctx context.Context, group scimmodel.DirectoryGroup, expectedVersion int64) (bool, error) {
	updated := false
	err := s.withinTransaction(ctx, func(executor identitytransaction.Executor) error {
		var operationErr error
		updated, operationErr = s.updateGroup(ctx, executor, group, expectedVersion)
		return operationErr
	})
	return updated, err
}

func (s *Store) updateGroup(ctx context.Context, executor identitytransaction.Executor, group scimmodel.DirectoryGroup, expectedVersion int64) (bool, error) {
	now := s.now().UnixMilli()
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_scim_groups", strings.TrimSpace(group.WorkspaceID)).
		Set("external_id", nullable(group.ExternalID)).Set("display_name", strings.TrimSpace(group.DisplayName)).
		Set("version", expectedVersion+1).Set("updated_at", now).
		Where(query.And(query.Equal("group_id", strings.TrimSpace(group.GroupID)), query.Equal("version", expectedVersion), query.Equal("deleted_at", int64(0)))).Build()
	if err != nil {
		return false, fmt.Errorf("build SCIM group update: %w", err)
	}
	result, err := executor.ExecContext(ctx, statement, arguments...)
	updated, err := exactlyOne(result, err)
	if err != nil || !updated {
		return updated, err
	}
	if err := s.replaceGroupMembers(ctx, executor, group.WorkspaceID, group.GroupID, group.MemberIDs, now); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) DeleteGroup(ctx context.Context, workspaceID, groupID string, expectedVersion int64) (bool, error) {
	deleted := false
	err := s.withinTransaction(ctx, func(executor identitytransaction.Executor) error {
		var operationErr error
		deleted, operationErr = s.deleteGroup(ctx, executor, workspaceID, groupID, expectedVersion)
		return operationErr
	})
	return deleted, err
}

func (s *Store) deleteGroup(ctx context.Context, executor identitytransaction.Executor, workspaceID, groupID string, expectedVersion int64) (bool, error) {
	now := s.now().UnixMilli()
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_scim_groups", strings.TrimSpace(workspaceID)).
		Set("version", expectedVersion+1).Set("updated_at", now).Set("deleted_at", now).
		Where(query.And(query.Equal("group_id", strings.TrimSpace(groupID)), query.Equal("version", expectedVersion), query.Equal("deleted_at", int64(0)))).Build()
	if err != nil {
		return false, fmt.Errorf("build SCIM group delete: %w", err)
	}
	result, err := executor.ExecContext(ctx, statement, arguments...)
	deleted, err := exactlyOne(result, err)
	if err != nil || !deleted {
		return deleted, err
	}
	statement, arguments, err = query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_scim_group_members", strings.TrimSpace(workspaceID)).
		Where(query.Equal("group_id", strings.TrimSpace(groupID))).Build()
	if err != nil {
		return false, fmt.Errorf("build SCIM group member delete: %w", err)
	}
	if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
		return false, err
	}
	return true, nil
}

type sqlExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (s *Store) replaceGroupMembers(ctx context.Context, execer sqlExecer, workspaceID, groupID string, memberIDs []string, now int64) error {
	statement, arguments, err := query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_scim_group_members", strings.TrimSpace(workspaceID)).
		Where(query.Equal("group_id", strings.TrimSpace(groupID))).Build()
	if err != nil {
		return fmt.Errorf("build SCIM group member reset: %w", err)
	}
	if _, err := execer.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, memberID := range memberIDs {
		memberID = strings.TrimSpace(memberID)
		if memberID == "" {
			continue
		}
		if _, duplicate := seen[memberID]; duplicate {
			continue
		}
		seen[memberID] = struct{}{}
		statement, arguments, err = query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_scim_group_members", strings.TrimSpace(workspaceID)).
			Columns("group_id", "user_id", "created_at").Values(strings.TrimSpace(groupID), memberID, now).Build()
		if err != nil {
			return fmt.Errorf("build SCIM group member create: %w", err)
		}
		if _, err := execer.ExecContext(ctx, statement, arguments...); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) execer(ctx context.Context) identitytransaction.Executor {
	if executor := identitytransaction.ExecutorFromContext(ctx); executor != nil {
		return executor
	}
	return s.backend.DB()
}

func (s *Store) withinTransaction(ctx context.Context, operation func(identitytransaction.Executor) error) error {
	if executor := identitytransaction.ExecutorFromContext(ctx); executor != nil {
		return operation(executor)
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := operation(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func exactlyOne(result sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func nullable(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func normalizedKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
