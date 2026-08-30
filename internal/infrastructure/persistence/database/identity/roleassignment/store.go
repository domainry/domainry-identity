package roleassignment

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

const InsertBatchSize = 40

var columns = []string{"id", "workspace_id", "user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at"}

type Backend interface {
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*ormbuilder.InsertBuilder, []string, ...string) *ormbuilder.InsertBuilder
}

type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
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
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).Columns(insertColumns...)
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
		nullIfBlank(assignment.WorkforceProfileID), nullIfBlank(assignment.BindingKey), nullIfBlank(assignment.ProfileID), assignment.Source, assignment.Status,
		nullIfBlank(assignment.ValidFrom), nullIfBlank(assignment.ValidUntil), nullIfBlank(assignment.GrantedBy), nullIfBlank(assignment.GrantReason),
		nullIfBlank(assignment.RevokedBy), nullIfBlank(assignment.RevokedAt), nullIfBlank(assignment.RevokeReason), nullableString(assignment.ExpiresAt), createdAt, now}
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
