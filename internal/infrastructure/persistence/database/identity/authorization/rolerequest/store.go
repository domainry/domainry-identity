package rolerequest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	QueryIdentityContext(context.Context, string, ...any) (*sql.Rows, error)
}
type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type AssignmentWriter func(context.Context, Execer, string, identitymodel.IdentityUserRoleAssignment) error
type Store struct {
	backend         Backend
	now             func() string
	writeAssignment AssignmentWriter
}

func New(backend Backend, now func() string, writer AssignmentWriter) *Store {
	return &Store{backend: backend, now: now, writeAssignment: writer}
}

func (s *Store) Create(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	if request.ID == "" || request.UserID == "" || len(request.RoleIDs) == 0 {
		return identitymodel.IdentityRoleRequest{}, fmt.Errorf("role request id, user id, and roles are required")
	}
	now := s.now()
	if request.CreatedAt == "" {
		request.CreatedAt = now
	}
	request.UpdatedAt = now
	if request.Status == "" {
		request.Status = "pending"
	}
	roleIDs, _ := json.Marshal(unique(request.RoleIDs))
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_role_requests", workspaceID).Columns("id", "user_id", "requested_by", "provider", "provider_subject", "role_ids_json", "status", "reason", "created_at", "updated_at", "reviewed_by", "reviewed_at", "review_note").Values(request.ID, request.UserID, nullable(request.RequestedBy), nullable(request.Provider), nullable(request.ProviderSubject), string(roleIDs), request.Status, nullable(request.Reason), request.CreatedAt, request.UpdatedAt, nullable(request.ReviewedBy), nullable(request.ReviewedAt), nullable(request.ReviewNote)).Build()
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, fmt.Errorf("build identity role request insert: %w", err)
	}
	if _, err := s.backend.DB().ExecContext(ctx, statement, arguments...); err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	return request, nil
}

func (s *Store) List(ctx context.Context, workspaceID, status, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return nil, err
	}
	predicates := []query.Predicate{}
	if strings.TrimSpace(status) != "" {
		predicates = append(predicates, query.Equal("status", status))
	}
	if strings.TrimSpace(userID) != "" {
		predicates = append(predicates, query.Equal("user_id", userID))
	}
	builder := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_role_requests", workspaceID).Columns("id", "user_id", "requested_by", "provider", "provider_subject", "role_ids_json", "status", "reason", "created_at", "updated_at", "reviewed_by", "reviewed_at", "review_note").OrderBy(query.Descending("created_at"), query.Ascending("id"))
	if len(predicates) > 0 {
		builder.Where(query.And(predicates...))
	}
	statement, arguments, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build identity role request list: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityRoleRequest{}
	for rows.Next() {
		var item identitymodel.IdentityRoleRequest
		var requestedBy, provider, providerSubject, reason, reviewedBy, reviewedAt, reviewNote sql.NullString
		var roleIDs string
		if err := rows.Scan(&item.ID, &item.UserID, &requestedBy, &provider, &providerSubject, &roleIDs, &item.Status, &reason, &item.CreatedAt, &item.UpdatedAt, &reviewedBy, &reviewedAt, &reviewNote); err != nil {
			return nil, err
		}
		item.RequestedBy, item.Provider, item.ProviderSubject = requestedBy.String, provider.String, providerSubject.String
		_ = json.Unmarshal([]byte(roleIDs), &item.RoleIDs)
		item.Reason, item.ReviewedBy, item.ReviewedAt, item.ReviewNote = reason.String, reviewedBy.String, reviewedAt.String, reviewNote.String
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) Update(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	if request.ID == "" {
		return fmt.Errorf("role request id is required")
	}
	if request.UpdatedAt == "" {
		request.UpdatedAt = s.now()
	}
	statement, arguments, err := s.update(workspaceID, request).Build()
	if err != nil {
		return fmt.Errorf("build identity role request update: %w", err)
	}
	_, err = s.backend.DB().ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) ApplyDecision(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, expectedStatus string) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, assignment := range assignments {
		if err := s.writeAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return err
		}
	}
	statement, arguments, err := s.update(workspaceID, request).Where(query.And(query.Equal("id", request.ID), query.Equal("status", expectedStatus))).Build()
	if err != nil {
		return fmt.Errorf("build identity role request decision: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.role_request_concurrent_decision"}
	}
	return tx.Commit()
}

func (s *Store) update(workspaceID string, request identitymodel.IdentityRoleRequest) *query.UpdateBuilder {
	roleIDs, _ := json.Marshal(unique(request.RoleIDs))
	return query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_role_requests", workspaceID).Set("role_ids_json", string(roleIDs)).Set("status", request.Status).Set("reason", nullable(request.Reason)).Set("updated_at", request.UpdatedAt).Set("reviewed_by", nullable(request.ReviewedBy)).Set("reviewed_at", nullable(request.ReviewedAt)).Set("review_note", nullable(request.ReviewNote)).Where(query.Equal("id", request.ID))
}
func workspace(value string) (string, error) {
	id, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
func nullable(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
func unique(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
