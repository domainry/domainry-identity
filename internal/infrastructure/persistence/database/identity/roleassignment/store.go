package roleassignment

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitydatascope "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/datascope"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

const InsertBatchSize = 40

var columns = []string{"id", "workspace_id", "user_id", "role_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at"}

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*query.InsertBuilder, []string, ...string) *query.InsertBuilder
}

type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type Store struct {
	backend Backend
	now     func() string
}

func New(backend Backend, now func() string) Store { return Store{backend: backend, now: now} }

func (s Store) Upsert(ctx context.Context, execer Execer, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
	workspaceID, err := workspaceIdentifier(workspaceID)
	if err != nil {
		return err
	}
	assignment, err = normalize(assignment)
	if err != nil {
		return err
	}
	return s.write(ctx, execer, workspaceID, []identitymodel.IdentityUserRoleAssignment{assignment})
}

// UpsertWithinDataScope validates the persisted target user and repeats the
// same workspace+scope predicate in the INSERT ... SELECT that performs the
// final upsert. The caller receives false when the target is outside scope.
func (s Store) UpsertWithinDataScope(ctx context.Context, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspaceID, err := workspaceIdentifier(workspaceID)
	if err != nil {
		return false, err
	}
	assignment, err = normalize(assignment)
	if err != nil {
		return false, err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	allowed, err := s.UpsertWithExecutorWithinDataScope(ctx, tx, workspaceID, assignment, scope)
	if err != nil || !allowed {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s Store) UpsertWithExecutorWithinDataScope(ctx context.Context, execer Execer, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspaceID, err := workspaceIdentifier(workspaceID)
	if err != nil {
		return false, err
	}
	assignment, err = normalize(assignment)
	if err != nil {
		return false, err
	}
	predicates := []query.Predicate{query.Equal("id", assignment.UserID)}
	if !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserPredicate(scope, query.Column("id"), query.Column("org_id")))
	}
	candidate, candidateArguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).
		Columns("id").Where(query.And(predicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build scoped identity user-role assignment candidate: %w", err)
	}
	var persistedUserID string
	if err := execer.QueryRowContext(ctx, candidate, candidateArguments...).Scan(&persistedUserID); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	allValues := values(workspaceID, assignment, s.now())
	projections := make([]query.Projection, len(allValues))
	for index := range allValues {
		projections[index] = query.Project(query.Value(allValues[index]))
	}
	source := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).
		Projections(projections...).Where(query.And(predicates...)).Limit(1)
	insert := query.NewInsertBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments").Columns(columns...).FromSelect(source)
	s.backend.ApplyUpsert(insert, []string{"workspace_id", "id"}, columns[2:]...)
	statement, arguments, err := insert.Build()
	if err != nil {
		return false, fmt.Errorf("build scoped identity user-role assignment upsert: %w", err)
	}
	result, err := execer.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if changed == 0 {
		return false, nil
	}
	return true, nil
}

func (s Store) UpsertBatch(ctx context.Context, execer Execer, workspaceID string, assignments []identitymodel.IdentityUserRoleAssignment) error {
	workspaceID, err := workspaceIdentifier(workspaceID)
	if err != nil {
		return err
	}
	normalized := make([]identitymodel.IdentityUserRoleAssignment, 0, len(assignments))
	positions := make(map[string]int, len(assignments))
	for _, assignment := range assignments {
		value, normalizeErr := normalize(assignment)
		if normalizeErr != nil {
			return normalizeErr
		}
		key := value.UserID + "\x00" + value.RoleID
		if position, ok := positions[key]; ok {
			normalized[position] = value
			continue
		}
		positions[key] = len(normalized)
		normalized = append(normalized, value)
	}
	for start := 0; start < len(normalized); start += InsertBatchSize {
		end := min(start+InsertBatchSize, len(normalized))
		if err := s.write(ctx, execer, workspaceID, normalized[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (s Store) write(ctx context.Context, execer Execer, workspaceID string, assignments []identitymodel.IdentityUserRoleAssignment) error {
	insertColumns := append([]string{columns[0]}, columns[2:]...)
	insert := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).Columns(insertColumns...)
	now := s.now()
	for _, assignment := range assignments {
		allValues := values(workspaceID, assignment, now)
		insert.Values(append([]any{allValues[0]}, allValues[2:]...)...)
	}
	s.backend.ApplyUpsert(insert, []string{"workspace_id", "id"}, insertColumns[1:]...)
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity user-role assignment upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}

func normalize(assignment identitymodel.IdentityUserRoleAssignment) (identitymodel.IdentityUserRoleAssignment, error) {
	if assignment.UserID == "" || assignment.RoleID == "" {
		return assignment, fmt.Errorf("user id and role id are required")
	}
	assignment.Source = strings.TrimSpace(assignment.Source)
	if assignment.Source == "" {
		assignment.Source = "manual"
	}
	assignment.Status = strings.TrimSpace(assignment.Status)
	if assignment.Status == "" {
		assignment.Status = "active"
	}
	if assignment.ValidUntil == "" && assignment.ExpiresAt != nil {
		assignment.ValidUntil = strings.TrimSpace(*assignment.ExpiresAt)
	}
	return assignment, nil
}

func values(workspaceID string, assignment identitymodel.IdentityUserRoleAssignment, now string) []any {
	createdAt := strings.TrimSpace(assignment.CreatedAt)
	if createdAt == "" {
		createdAt = now
	}
	return []any{identifier("identity_user_role", workspaceID, assignment.UserID, assignment.RoleID), workspaceID, assignment.UserID, assignment.RoleID,
		nullIfBlank(assignment.BindingKey), nullIfBlank(assignment.ProfileID), assignment.Source, assignment.Status,
		timevalue.Millis(assignment.ValidFrom), timevalue.Millis(assignment.ValidUntil), nullIfBlank(assignment.GrantedBy), nullIfBlank(assignment.GrantReason),
		nullIfBlank(assignment.RevokedBy), timevalue.Millis(assignment.RevokedAt), nullIfBlank(assignment.RevokeReason), timevalue.Millis(nullableString(assignment.ExpiresAt)), timevalue.Millis(createdAt), timevalue.Millis(now)}
}

func workspaceIdentifier(value string) (string, error) {
	workspace, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return workspace.String(), nil
}

func identifier(parts ...string) string {
	value := strings.Join(parts, "_")
	return strings.NewReplacer(".", "_", ":", "_", "/", "_").Replace(value)
}

func nullIfBlank(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullableString(value *string) any {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	return *value
}
