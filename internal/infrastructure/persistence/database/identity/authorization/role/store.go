package role

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitydatascope "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/datascope"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
	"github.com/domainry/domainry-orm/batch"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	MaxParameters() int
	ApplyUpsert(*query.InsertBuilder, []string, ...string) *query.InsertBuilder
	QueryIdentityContext(context.Context, string, ...any) (*sql.Rows, error)
}

type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type Store struct {
	backend Backend
	now     func() string
}

func New(backend Backend, now func() string) *Store { return &Store{backend: backend, now: now} }

func (s *Store) List(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	filter := query.Equal("scope_type", string(identitymodel.IdentityRoleScopeGlobal))
	if workspaceID != "" {
		normalizedWorkspace, err := workspace(workspaceID)
		if err != nil {
			return nil, err
		}
		workspaceID = normalizedWorkspace
		filter = query.Or(
			filter,
			query.And(
				query.Equal("scope_type", string(identitymodel.IdentityRoleScopeTenant)),
				query.Equal("workspace_id", workspaceID),
			),
		)
	}
	statement, arguments, err := query.NewSelectBuilder(s.backend.SQLRenderer(), "_identity_roles").
		Columns("id", "role_id", "workspace_id", "scope_type", "source_owner", "role_key", "label", "description", "definition_json", "status").
		Where(filter).
		OrderBy(query.Ascending("scope_type"), query.Ascending("role_key")).
		Build()
	if err != nil {
		return nil, fmt.Errorf("build identity role list: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityRole{}
	for rows.Next() {
		var item identitymodel.IdentityRole
		var persistedWorkspace sql.NullString
		var scopeType, definitionJSON, status string
		if err := rows.Scan(&item.ID, &item.RoleID, &persistedWorkspace, &scopeType, &item.SourceOwner, &item.Key, &item.Label, &item.Description, &definitionJSON, &status); err != nil {
			return nil, err
		}
		item.WorkspaceID = persistedWorkspace.String
		item.ScopeType = identitymodel.IdentityRoleScope(scopeType)
		item.Status = identitymodel.IdentityStatus(status)
		if err := json.Unmarshal([]byte(definitionJSON), &item.Definition); err != nil {
			return nil, fmt.Errorf("decode identity role %q definition: %w", item.RoleID, err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) Upsert(ctx context.Context, workspaceID string, item identitymodel.IdentityRole) error {
	return s.UpsertBatchWithExecutor(ctx, s.backend.DB(), workspaceID, []identitymodel.IdentityRole{item})
}

func (s *Store) UpsertWithExecutor(ctx context.Context, execer Execer, workspaceID string, item identitymodel.IdentityRole) error {
	return s.UpsertBatchWithExecutor(ctx, execer, workspaceID, []identitymodel.IdentityRole{item})
}

// UpsertBatchWithExecutor normalizes the complete role set before issuing
// bounded multi-row UPSERTs. The caller owns the transaction lifecycle, which
// lets workspace provisioning commit roles together with users, assignments,
// credentials and PermissionDefinitions without one database write per role.
func (s *Store) UpsertBatchWithExecutor(ctx context.Context, execer Execer, workspaceID string, items []identitymodel.IdentityRole) error {
	if execer == nil {
		return fmt.Errorf("role executor is required")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	normalized := make([]identitymodel.IdentityRole, 0, len(items))
	positionByID := make(map[string]int, len(items))
	for _, item := range items {
		item.RoleID = strings.TrimSpace(item.RoleID)
		item.Key = strings.TrimSpace(item.Key)
		if item.RoleID == "" {
			return fmt.Errorf("role id is required")
		}
		if item.Key == "" {
			item.Key = item.RoleID
		}
		if item.ScopeType == "" {
			item.ScopeType = identitymodel.IdentityRoleScopeTenant
		}
		switch item.ScopeType {
		case identitymodel.IdentityRoleScopeGlobal:
			item.WorkspaceID = ""
			item.SourceOwner = strings.TrimSpace(item.SourceOwner)
			if item.SourceOwner == "" {
				return fmt.Errorf("global role %q source owner is required", item.Key)
			}
		case identitymodel.IdentityRoleScopeTenant:
			normalizedWorkspace, normalizeErr := workspace(workspaceID)
			if normalizeErr != nil {
				return normalizeErr
			}
			item.WorkspaceID = normalizedWorkspace
			item.SourceOwner = "tenant:" + normalizedWorkspace
		default:
			return fmt.Errorf("role %q scope type %q is invalid", item.Key, item.ScopeType)
		}
		if item.Status == "" {
			item.Status = identitymodel.IdentityStatusActive
		}
		if roleDefinitionProvided(item.Definition) {
			item.Definition.Key = item.Key
			if strings.TrimSpace(item.Definition.Name) == "" {
				item.Definition.Name = item.Label
			}
			if strings.TrimSpace(item.Definition.Description) == "" {
				item.Definition.Description = item.Description
			}
		}
		if position, duplicate := positionByID[item.RoleID]; duplicate {
			normalized[position] = item
			continue
		}
		positionByID[item.RoleID] = len(normalized)
		normalized = append(normalized, item)
	}
	const parametersPerRole = 11
	ranges, err := (batch.Parameters{Max: s.backend.MaxParameters(), PerItem: parametersPerRole}).Ranges(len(normalized))
	if err != nil {
		return fmt.Errorf("plan identity role upsert batches: %w", err)
	}
	now := timevalue.Millis(s.now())
	for _, batchRange := range ranges {
		insert := query.NewInsertBuilder(s.backend.SQLRenderer(), "_identity_roles").
			Columns("role_id", "workspace_id", "scope_type", "source_owner", "role_key", "label", "description", "definition_json", "status", "created_at", "updated_at")
		for _, item := range normalized[batchRange.Start:batchRange.End] {
			definitionJSON, marshalErr := json.Marshal(item.Definition)
			if marshalErr != nil {
				return fmt.Errorf("encode identity role %q definition: %w", item.RoleID, marshalErr)
			}
			insert.Values(item.RoleID, nullableWorkspace(item.WorkspaceID), string(item.ScopeType), item.SourceOwner, item.Key, item.Label, item.Description, string(definitionJSON), string(item.Status), now, now)
		}
		s.backend.ApplyUpsert(insert, []string{"role_id"}, "workspace_id", "scope_type", "source_owner", "role_key", "label", "description", "definition_json", "status", "updated_at")
		statement, arguments, buildErr := insert.Build()
		if buildErr != nil {
			return fmt.Errorf("build identity role batch upsert: %w", buildErr)
		}
		if _, execErr := execer.ExecContext(ctx, statement, arguments...); execErr != nil {
			return fmt.Errorf("upsert identity role batch: %w", execErr)
		}
	}
	return nil
}

func (s *Store) Remove(ctx context.Context, workspaceID, roleID string) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	roleID = strings.TrimSpace(roleID)
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	statement, arguments, err := query.NewDeleteBuilder(s.backend.SQLRenderer(), "_identity_roles").Where(query.And(
		query.Equal("role_id", roleID),
		query.Equal("scope_type", string(identitymodel.IdentityRoleScopeTenant)),
		query.Equal("workspace_id", workspaceID),
	)).Build()
	if err != nil {
		return fmt.Errorf("build identity role delete: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("tenant role not found or global role is read-only: %s", roleID)
	}
	statement, arguments, err = query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).Where(query.Equal("role_id", roleID)).Build()
	if err != nil {
		return fmt.Errorf("build identity user-role assignment delete: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	statement, arguments, err = query.NewDeleteBuilder(s.backend.SQLRenderer(), "_identity_role_menu_assignments").Where(query.Equal("role_id", roleID)).Build()
	if err != nil {
		return fmt.Errorf("build identity role-menu assignment delete: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	return tx.Commit()
}

func nullableWorkspace(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func roleDefinitionProvided(definition identitymodel.RoleSchema) bool {
	return strings.TrimSpace(definition.Key) != "" || strings.TrimSpace(definition.Name) != "" ||
		len(definition.Permissions) != 0 || len(definition.FieldPermissions) != 0 ||
		len(definition.ReferencePermissions) != 0 || len(definition.ExportRules) != 0
}

func (s *Store) RemoveUserAssignment(ctx context.Context, workspaceID, userID, roleID string) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	statement, arguments, err := query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).Where(query.And(query.Equal("user_id", userID), query.Equal("role_id", roleID))).Build()
	if err != nil {
		return fmt.Errorf("build identity user-role assignment delete: %w", err)
	}
	_, err = s.backend.DB().ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) RemoveUserAssignmentWithinDataScope(ctx context.Context, workspaceID, userID, roleID string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return false, err
	}
	userID, roleID = strings.TrimSpace(userID), strings.TrimSpace(roleID)
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	candidatePredicates := []query.Predicate{query.Equal("user_id", userID)}
	if !scope.Unrestricted {
		candidatePredicates = append(candidatePredicates, identitydatascope.UserPredicate(scope, query.Column("user_id"), query.Column("org_id")))
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).
		Columns("user_id").Where(query.And(candidatePredicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build scoped identity user-role removal candidate: %w", err)
	}
	var persistedUserID string
	if err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&persistedUserID); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	predicates := []query.Predicate{query.Equal("user_id", userID), query.Equal("role_id", roleID)}
	if !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_user_role_assignments", "user_id"), scope))
	}
	statement, arguments, err = query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).
		Where(query.And(predicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build scoped identity user-role assignment delete: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ListUserAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return s.ListUserAssignmentsWithinDataScope(ctx, workspaceID, userID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *Store) ListUserAssignmentsWithinDataScope(ctx context.Context, workspaceID, userID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUserRoleAssignment, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).Columns("user_id", "role_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at").OrderBy(query.Ascending("user_id"), query.Ascending("role_id"))
	predicates := []query.Predicate{}
	if strings.TrimSpace(userID) != "" {
		predicates = append(predicates, query.Equal("user_id", userID))
	}
	if !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_user_role_assignments", "user_id"), scope))
	}
	if len(predicates) > 0 {
		builder.Where(query.And(predicates...))
	}
	statement, arguments, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build identity user-role assignment list: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityUserRoleAssignment{}
	for rows.Next() {
		var item identitymodel.IdentityUserRoleAssignment
		var bindingKey, profileID, grantedBy, grantReason, revokedBy, revokeReason sql.NullString
		var validFrom, validUntil, revokedAt, expiresAt, createdAt, updatedAt int64
		if err := rows.Scan(&item.UserID, &item.RoleID, &bindingKey, &profileID, &item.Source, &item.Status, &validFrom, &validUntil, &grantedBy, &grantReason, &revokedBy, &revokedAt, &revokeReason, &expiresAt, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		item.BindingKey, item.ProfileID = bindingKey.String, profileID.String
		item.ValidFrom, item.ValidUntil, item.GrantedBy, item.GrantReason = timevalue.String(validFrom), timevalue.String(validUntil), grantedBy.String, grantReason.String
		item.RevokedBy, item.RevokedAt, item.RevokeReason = revokedBy.String, timevalue.String(revokedAt), revokeReason.String
		item.CreatedAt, item.UpdatedAt = timevalue.String(createdAt), timevalue.String(updatedAt)
		if expiresAt != 0 {
			value := timevalue.String(expiresAt)
			item.ExpiresAt = &value
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func workspace(value string) (string, error) {
	id, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
