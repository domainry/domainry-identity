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
	identitydatascope "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/datascope"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
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
type ScopedAssignmentWriter func(context.Context, Execer, string, identitymodel.IdentityUserRoleAssignment, identitymodel.IdentityDataScopeFilter) (bool, error)
type Store struct {
	backend               Backend
	now                   func() string
	writeAssignment       AssignmentWriter
	writeScopedAssignment ScopedAssignmentWriter
}

func New(backend Backend, now func() string, writer AssignmentWriter, scopedWriter ...ScopedAssignmentWriter) *Store {
	store := &Store{backend: backend, now: now, writeAssignment: writer}
	if len(scopedWriter) > 0 {
		store.writeScopedAssignment = scopedWriter[0]
	}
	return store
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
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_role_requests", workspaceID).Columns("id", "user_id", "requested_by", "provider", "provider_subject", "role_ids_json", "status", "reason", "created_at", "updated_at", "reviewed_by", "reviewed_at", "review_note").Values(request.ID, request.UserID, nullable(request.RequestedBy), nullable(request.Provider), nullable(request.ProviderSubject), string(roleIDs), request.Status, nullable(request.Reason), timevalue.Millis(request.CreatedAt), timevalue.Millis(request.UpdatedAt), nullable(request.ReviewedBy), timevalue.Millis(request.ReviewedAt), nullable(request.ReviewNote)).Build()
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, fmt.Errorf("build identity role request insert: %w", err)
	}
	if _, err := s.backend.DB().ExecContext(ctx, statement, arguments...); err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	return request, nil
}

func (s *Store) List(ctx context.Context, workspaceID, status, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	return s.ListWithinDataScope(ctx, workspaceID, status, userID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *Store) ListWithinDataScope(ctx context.Context, workspaceID, status, userID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityRoleRequest, error) {
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
	if !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_role_requests", "user_id"), scope))
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
		var requestedBy, provider, providerSubject, reason, reviewedBy, reviewNote sql.NullString
		var createdAt, updatedAt, reviewedAt int64
		var roleIDs string
		if err := rows.Scan(&item.ID, &item.UserID, &requestedBy, &provider, &providerSubject, &roleIDs, &item.Status, &reason, &createdAt, &updatedAt, &reviewedBy, &reviewedAt, &reviewNote); err != nil {
			return nil, err
		}
		item.RequestedBy, item.Provider, item.ProviderSubject = requestedBy.String, provider.String, providerSubject.String
		_ = json.Unmarshal([]byte(roleIDs), &item.RoleIDs)
		item.Reason, item.ReviewedBy, item.ReviewedAt, item.ReviewNote = reason.String, reviewedBy.String, timevalue.String(reviewedAt), reviewNote.String
		item.CreatedAt, item.UpdatedAt = timevalue.String(createdAt), timevalue.String(updatedAt)
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
	updated, err := s.applyDecision(ctx, workspaceID, request, assignments, expectedStatus, identitymodel.IdentityDataScopeFilter{Unrestricted: true}, false)
	if err != nil {
		return err
	}
	if !updated {
		return &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.role_request_concurrent_decision"}
	}
	return nil
}

func (s *Store) ApplyDecisionWithinDataScope(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, expectedStatus string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	return s.applyDecision(ctx, workspaceID, request, assignments, expectedStatus, scope, true)
}

func (s *Store) applyDecision(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, expectedStatus string, scope identitymodel.IdentityDataScopeFilter, enforceScope bool) (bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return false, err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	candidatePredicates := []query.Predicate{query.Equal("id", request.ID)}
	if !scope.Unrestricted {
		candidatePredicates = append(candidatePredicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_role_requests", "user_id"), scope))
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_role_requests", workspaceID).
		Columns("status").Where(query.And(candidatePredicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build scoped identity role request decision candidate: %w", err)
	}
	var persistedStatus string
	if err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&persistedStatus); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if persistedStatus != expectedStatus {
		return false, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.role_request_concurrent_decision"}
	}
	for _, assignment := range assignments {
		if enforceScope && s.writeScopedAssignment == nil {
			return false, fmt.Errorf("scoped identity role assignment writer is unavailable")
		}
		if enforceScope {
			allowed, writeErr := s.writeScopedAssignment(ctx, tx, workspaceID, assignment, scope)
			if writeErr != nil || !allowed {
				return false, writeErr
			}
		} else if err := s.writeAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return false, err
		}
	}
	updatePredicates := []query.Predicate{query.Equal("id", request.ID), query.Equal("status", expectedStatus)}
	if !scope.Unrestricted {
		updatePredicates = append(updatePredicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_role_requests", "user_id"), scope))
	}
	statement, arguments, err = s.update(workspaceID, request).Where(query.And(updatePredicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build identity role request decision: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected != 1 {
		return false, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.role_request_concurrent_decision"}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) update(workspaceID string, request identitymodel.IdentityRoleRequest) *query.UpdateBuilder {
	roleIDs, _ := json.Marshal(unique(request.RoleIDs))
	return query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_role_requests", workspaceID).Set("role_ids_json", string(roleIDs)).Set("status", request.Status).Set("reason", nullable(request.Reason)).Set("updated_at", timevalue.Millis(request.UpdatedAt)).Set("reviewed_by", nullable(request.ReviewedBy)).Set("reviewed_at", timevalue.Millis(request.ReviewedAt)).Set("review_note", nullable(request.ReviewNote)).Where(query.Equal("id", request.ID))
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
