package accessreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	identitydatascope "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/datascope"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

var _ identityrepository.IdentityAccessReviewRepository = (*Store)(nil)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
}

type RoleAssignmentWriter func(context.Context, *sql.Tx, string, identitymodel.IdentityUserRoleAssignment) error
type ScopedRoleAssignmentWriter func(context.Context, *sql.Tx, string, identitymodel.IdentityUserRoleAssignment, identitymodel.IdentityDataScopeFilter) (bool, error)

type Store struct {
	backend                   Backend
	writeRoleAssignment       RoleAssignmentWriter
	writeScopedRoleAssignment ScopedRoleAssignmentWriter
	now                       func() string
}

func New(backend Backend, now func() string, writeRoleAssignment RoleAssignmentWriter, scopedWriter ...ScopedRoleAssignmentWriter) *Store {
	store := &Store{backend: backend, now: now, writeRoleAssignment: writeRoleAssignment}
	if len(scopedWriter) > 0 {
		store.writeScopedRoleAssignment = scopedWriter[0]
	}
	return store
}

type Queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type accessReviewDecisionScopeContextKey struct{}
type accessReviewDecisionScopeContext struct {
	filter  identitymodel.IdentityDataScopeFilter
	allowed *bool
}

func (s *Store) CreateIdentityAccessReview(ctx context.Context, review identitymodel.IdentityAccessReview) error {
	workspaceID, err := identityWorkspaceID(review.WorkspaceID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(review.ID) == "" || strings.TrimSpace(review.CreatedBy) == "" || len(review.Items) == 0 {
		return fmt.Errorf("identity access review is invalid")
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_access_reviews", workspaceID).
		Columns("id", "period_start", "period_end", "due_at", "status", "created_by", "created_at", "updated_at").
		Values(review.ID, review.PeriodStart, review.PeriodEnd, review.DueAt, review.Status, review.CreatedBy, review.CreatedAt, review.UpdatedAt).Build()
	if err != nil {
		return fmt.Errorf("build identity access review insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return normalizeAccessReviewCreateError(err)
	}
	items := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_access_review_items", workspaceID).
		Columns("id", "review_id", "user_id", "role_id", "role_key", "binding_key", "profile_id", "risk_level", "priority", "priority_reasons_json", "last_used_at", "status", "decision", "replacement_role_id", "expires_at", "reviewer_id", "reason", "decided_at", "version", "created_at", "updated_at")
	for _, item := range review.Items {

		priorityReasonsJSON, _ := json.Marshal(item.PriorityReasons)
		items.Values(
			item.ID, review.ID, item.UserID, item.RoleID, item.RoleKey,
			nullIfBlank(item.BindingKey), nullIfBlank(item.ProfileID),
			item.RiskLevel, item.Priority, string(priorityReasonsJSON), nullIfBlank(item.LastUsedAt),
			item.Status, nullIfBlank(string(item.Decision)), nullIfBlank(item.ReplacementRoleID),
			nullIfBlank(item.ExpiresAt), nullIfBlank(item.ReviewerID), nullIfBlank(item.Reason), nullIfBlank(item.DecidedAt),
			item.Version, item.CreatedAt, item.UpdatedAt)
	}
	statement, arguments, err = items.Build()
	if err != nil {
		return fmt.Errorf("build identity access review items insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateIdentityAccessReviewWithinDataScope(ctx context.Context, review identitymodel.IdentityAccessReview, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspaceID, err := identityWorkspaceID(review.WorkspaceID)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(review.ID) == "" || strings.TrimSpace(review.CreatedBy) == "" || len(review.Items) == 0 {
		return false, fmt.Errorf("identity access review is invalid")
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_access_reviews", workspaceID).
		Columns("id", "period_start", "period_end", "due_at", "status", "created_by", "created_at", "updated_at").
		Values(review.ID, review.PeriodStart, review.PeriodEnd, review.DueAt, review.Status, review.CreatedBy, review.CreatedAt, review.UpdatedAt).Build()
	if err != nil {
		return false, fmt.Errorf("build identity access review insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return false, normalizeAccessReviewCreateError(err)
	}
	columns := []string{"workspace_id", "id", "review_id", "user_id", "role_id", "role_key", "binding_key", "profile_id", "risk_level", "priority", "priority_reasons_json", "last_used_at", "status", "decision", "replacement_role_id", "expires_at", "reviewer_id", "reason", "decided_at", "version", "created_at", "updated_at"}
	for _, item := range review.Items {
		priorityReasonsJSON, _ := json.Marshal(item.PriorityReasons)
		values := []any{
			workspaceID, item.ID, review.ID, item.UserID, item.RoleID, item.RoleKey,
			nullIfBlank(item.BindingKey), nullIfBlank(item.ProfileID), item.RiskLevel, item.Priority,
			string(priorityReasonsJSON), nullIfBlank(item.LastUsedAt), item.Status, nullIfBlank(string(item.Decision)),
			nullIfBlank(item.ReplacementRoleID), nullIfBlank(item.ExpiresAt), nullIfBlank(item.ReviewerID),
			nullIfBlank(item.Reason), nullIfBlank(item.DecidedAt), item.Version, item.CreatedAt, item.UpdatedAt,
		}
		projections := make([]query.Projection, len(values))
		for index := range values {
			projections[index] = query.Project(query.Value(values[index]))
		}
		predicates := []query.Predicate{query.Equal("id", item.UserID)}
		if !scope.Unrestricted {
			predicates = append(predicates, identitydatascope.UserPredicate(scope, query.Column("id"), query.Column("org_id")))
		}
		source := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).
			Projections(projections...).Where(query.And(predicates...)).Limit(1)
		statement, arguments, err = query.NewInsertBuilder(s.backend.SQLRenderer(), "_identity_access_review_items").
			Columns(columns...).FromSelect(source).Build()
		if err != nil {
			return false, fmt.Errorf("build scoped identity access review item insert: %w", err)
		}
		result, executeErr := tx.ExecContext(ctx, statement, arguments...)
		if executeErr != nil {
			return false, executeErr
		}
		changed, countErr := result.RowsAffected()
		if countErr != nil {
			return false, countErr
		}
		if changed != 1 {
			return false, nil
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func normalizeAccessReviewCreateError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique") || strings.Contains(message, "duplicate") {
		return &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.access_review_exists", Err: err}
	}
	return err
}

func (s *Store) ListIdentityAccessReviews(ctx context.Context, workspaceID, status string) ([]identitymodel.IdentityAccessReview, error) {
	return s.ListIdentityAccessReviewsWithinDataScope(ctx, workspaceID, status, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *Store) ListIdentityAccessReviewsWithinDataScope(ctx context.Context, workspaceID, status string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityAccessReview, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_access_reviews", workspaceID).
		Columns("id", "period_start", "period_end", "due_at", "status", "created_by", "created_at", "updated_at").
		OrderBy(query.Descending("created_at"), query.Ascending("id"))
	predicates := []query.Predicate{}
	if status = strings.TrimSpace(status); status != "" {
		predicates = append(predicates, query.Equal("status", status))
	}
	if !scope.Unrestricted {
		predicates = append(predicates, query.Exists("_identity_access_review_items", query.And(
			query.Equal("workspace_id", workspaceID),
			query.EqualExpressions(query.Column("review_id"), query.TableColumn("_identity_access_reviews", "id")),
			identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_access_review_items", "user_id"), scope),
		)))
	}
	if len(predicates) > 0 {
		builder.Where(query.And(predicates...))
	}
	statement, arguments, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build identity access review list: %w", err)
	}
	rows, err := s.backend.DB().QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	out := []identitymodel.IdentityAccessReview{}
	for rows.Next() {
		var review identitymodel.IdentityAccessReview
		var reviewStatus string
		if err := rows.Scan(&review.ID, &review.PeriodStart, &review.PeriodEnd, &review.DueAt, &reviewStatus, &review.CreatedBy, &review.CreatedAt, &review.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		review.WorkspaceID, review.Status = workspaceID, identitymodel.IdentityAccessReviewStatus(reviewStatus)
		out = append(out, review)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	for index := range out {
		items, err := s.ListItemsWithinDataScope(ctx, workspaceID, out[index].ID, scope)
		if err != nil {
			return nil, err
		}
		out[index].Items = items
	}
	return out, nil
}

func (s *Store) GetIdentityAccessReviewItem(ctx context.Context, workspaceID, itemID string) (identitymodel.IdentityAccessReviewItem, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityAccessReviewItem{}, false, err
	}
	return s.LoadItem(ctx, s.backend.DB(), workspaceID, strings.TrimSpace(itemID))
}

func (s *Store) GetIdentityAccessReviewItemWithinDataScope(ctx context.Context, workspaceID, itemID string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewItem, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityAccessReviewItem{}, false, err
	}
	return s.LoadItemWithinDataScope(ctx, s.backend.DB(), workspaceID, strings.TrimSpace(itemID), scope)
}

func (s *Store) GetIdentityAccessReviewDecisionReceipt(ctx context.Context, workspaceID, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, err
	}
	return s.LoadReceipt(ctx, s.backend.DB(), workspaceID, strings.TrimSpace(itemID), strings.TrimSpace(idempotencyKey))
}

func (s *Store) GetIdentityAccessReviewDecisionReceiptWithinDataScope(ctx context.Context, workspaceID, itemID, idempotencyKey string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, err
	}
	return s.loadReceipt(ctx, s.backend.DB(), workspaceID, strings.TrimSpace(itemID), strings.TrimSpace(idempotencyKey), scope)
}

func (s *Store) ApplyIdentityAccessReviewDecision(ctx context.Context, mutation identitymodel.IdentityAccessReviewDecisionMutation) (identitymodel.IdentityAccessReviewDecisionReceipt, error) {
	decisionScope, scopedDecision := ctx.Value(accessReviewDecisionScopeContextKey{}).(accessReviewDecisionScopeContext)
	workspaceID, err := identityWorkspaceID(mutation.WorkspaceID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	mutation.WorkspaceID = workspaceID
	mutation.ItemID = strings.TrimSpace(mutation.ItemID)
	mutation.ReviewerID = strings.TrimSpace(mutation.ReviewerID)
	mutation.Request.IdempotencyKey = strings.TrimSpace(mutation.Request.IdempotencyKey)
	mutation.RequestFingerprint = strings.TrimSpace(mutation.RequestFingerprint)
	if mutation.ItemID == "" || mutation.ReviewerID == "" || mutation.Request.IdempotencyKey == "" || mutation.RequestFingerprint == "" {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, fmt.Errorf("identity access review decision is invalid")
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	defer tx.Rollback()
	loadReceipt := s.LoadReceipt
	if scopedDecision {
		loadReceipt = func(ctx context.Context, queryer Queryer, workspaceID, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
			return s.loadReceipt(ctx, queryer, workspaceID, itemID, idempotencyKey, decisionScope.filter)
		}
	}
	if receipt, found, err := loadReceipt(ctx, tx, workspaceID, mutation.ItemID, mutation.Request.IdempotencyKey); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	} else if found {
		if decisionScope.allowed != nil {
			*decisionScope.allowed = true
		}
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.idempotency_key_reused"}
		}
		receipt.Replayed = true
		return receipt, nil
	}
	loadItem := s.LoadItem
	if scopedDecision {
		loadItem = func(ctx context.Context, queryer Queryer, workspaceID, itemID string) (identitymodel.IdentityAccessReviewItem, bool, error) {
			return s.LoadItemWithinDataScope(ctx, queryer, workspaceID, itemID, decisionScope.filter)
		}
	}
	item, found, err := loadItem(ctx, tx, workspaceID, mutation.ItemID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	if !found {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.access_review_item_not_found"}
	}
	if decisionScope.allowed != nil {
		*decisionScope.allowed = true
	}
	if item.Status != "pending" || item.Version != mutation.Request.ExpectedVersion {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.access_review_concurrent_decision"}
	}
	assignment, assignmentFound, err := s.LoadAssignment(ctx, tx, workspaceID, item.UserID, item.RoleID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	now := s.now()
	switch mutation.Request.Decision {
	case identitymodel.IdentityAccessReviewKeep:
	case identitymodel.IdentityAccessReviewRevoke:
		if assignmentFound {
			if err := s.deleteIdentityAccessReviewAssignment(ctx, tx, workspaceID, item.UserID, item.RoleID, decisionScope.filter, scopedDecision); err != nil {
				return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
			}
		}
	case identitymodel.IdentityAccessReviewReduceScope:
		if !assignmentFound {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.access_review_assignment_missing"}
		}
		replacement := strings.TrimSpace(mutation.Request.ReplacementRoleID)
		if replacement == "" || replacement == item.RoleID {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.access_review_replacement_role_required"}
		}
		if _, found, err := s.LoadRole(ctx, tx, workspaceID, replacement); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		} else if !found {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_not_found"}
		}
		if err := s.deleteIdentityAccessReviewAssignment(ctx, tx, workspaceID, item.UserID, item.RoleID, decisionScope.filter, scopedDecision); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
		assignment.RoleID, assignment.Source, assignment.GrantedBy, assignment.GrantReason = replacement, "access_review", mutation.ReviewerID, mutation.Request.Reason
		assignment.CreatedAt, assignment.UpdatedAt = now, now
		if err := s.writeAccessReviewRoleAssignment(ctx, tx, workspaceID, assignment, decisionScope.filter, scopedDecision); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
	case identitymodel.IdentityAccessReviewSetExpiry:
		if !assignmentFound {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.access_review_assignment_missing"}
		}
		expiresAt := strings.TrimSpace(mutation.Request.ExpiresAt)
		assignment.ExpiresAt, assignment.ValidUntil = &expiresAt, expiresAt
		assignment.Source, assignment.GrantedBy, assignment.GrantReason = "access_review", mutation.ReviewerID, mutation.Request.Reason
		if err := s.writeAccessReviewRoleAssignment(ctx, tx, workspaceID, assignment, decisionScope.filter, scopedDecision); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
	default:
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.access_review_decision_invalid"}
	}
	item.Status, item.Decision, item.ReplacementRoleID, item.ExpiresAt = "decided", mutation.Request.Decision, strings.TrimSpace(mutation.Request.ReplacementRoleID), strings.TrimSpace(mutation.Request.ExpiresAt)
	item.ReviewerID, item.Reason, item.DecidedAt, item.UpdatedAt, item.Version = mutation.ReviewerID, strings.TrimSpace(mutation.Request.Reason), now, now, item.Version+1
	itemPredicates := []query.Predicate{query.Equal("id", item.ID), query.Equal("status", "pending"), query.Equal("version", mutation.Request.ExpectedVersion)}
	if scopedDecision && !decisionScope.filter.Unrestricted {
		itemPredicates = append(itemPredicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_access_review_items", "user_id"), decisionScope.filter))
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_access_review_items", workspaceID).
		Set("status", item.Status).Set("decision", item.Decision).Set("replacement_role_id", nullIfBlank(item.ReplacementRoleID)).
		Set("expires_at", nullIfBlank(item.ExpiresAt)).Set("reviewer_id", item.ReviewerID).Set("reason", item.Reason).
		Set("decided_at", item.DecidedAt).Set("updated_at", item.UpdatedAt).Set("version", item.Version).
		Where(query.And(itemPredicates...)).Build()
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, fmt.Errorf("build identity access review decision: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.access_review_concurrent_decision"}
	}
	var pending int
	statement, arguments, err = query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_access_review_items", workspaceID).
		Projections(query.Project(query.CountAll())).Where(query.And(query.Equal("review_id", item.ReviewID), query.Equal("status", "pending"))).Build()
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, fmt.Errorf("build pending identity access review count: %w", err)
	}
	if err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&pending); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	reviewStatus := identitymodel.IdentityAccessReviewOpen
	if pending == 0 {
		reviewStatus = identitymodel.IdentityAccessReviewCompleted
	}
	statement, arguments, err = query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_access_reviews", workspaceID).
		Set("status", reviewStatus).Set("updated_at", now).Where(query.Equal("id", item.ReviewID)).Build()
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, fmt.Errorf("build identity access review status update: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	receipt := identitymodel.IdentityAccessReviewDecisionReceipt{
		ID:          identityID("identity_access_review_receipt", workspaceID, item.ID, mutation.Request.IdempotencyKey),
		WorkspaceID: workspaceID, ItemID: item.ID, IdempotencyKey: mutation.Request.IdempotencyKey,
		RequestFingerprint: mutation.RequestFingerprint, Item: item, CreatedAt: now,
	}

	resultJSON, _ := json.Marshal(receipt)
	statement, arguments, err = query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_access_review_receipts", workspaceID).
		Columns("id", "item_id", "idempotency_key", "request_fingerprint", "result_json", "created_at").
		Values(receipt.ID, item.ID, receipt.IdempotencyKey, receipt.RequestFingerprint, string(resultJSON), receipt.CreatedAt).Build()
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, fmt.Errorf("build identity access review receipt: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	return receipt, nil
}

func (s *Store) ApplyIdentityAccessReviewDecisionWithinDataScope(ctx context.Context, mutation identitymodel.IdentityAccessReviewDecisionMutation, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	allowed := false
	ctx = context.WithValue(ctx, accessReviewDecisionScopeContextKey{}, accessReviewDecisionScopeContext{filter: scope, allowed: &allowed})
	receipt, err := s.ApplyIdentityAccessReviewDecision(ctx, mutation)
	return receipt, allowed, err
}

func (s *Store) writeAccessReviewRoleAssignment(ctx context.Context, tx *sql.Tx, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter, scoped bool) error {
	if !scoped {
		return s.writeRoleAssignment(ctx, tx, workspaceID, assignment)
	}
	if s.writeScopedRoleAssignment == nil {
		return fmt.Errorf("scoped identity role assignment writer is unavailable")
	}
	allowed, err := s.writeScopedRoleAssignment(ctx, tx, workspaceID, assignment, scope)
	if err != nil {
		return err
	}
	if !allowed {
		return &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.identity.data_scope_denied"}
	}
	return nil
}

func (s *Store) deleteIdentityAccessReviewAssignment(ctx context.Context, tx *sql.Tx, workspaceID, userID, roleID string, scope identitymodel.IdentityDataScopeFilter, scoped bool) error {
	predicates := []query.Predicate{query.Equal("user_id", userID), query.Equal("role_id", roleID)}
	if scoped && !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_user_role_assignments", "user_id"), scope))
	}
	statement, arguments, err := query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).
		Where(query.And(predicates...)).Build()
	if err != nil {
		return fmt.Errorf("build identity access review assignment delete: %w", err)
	}
	_, err = tx.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) ListItems(ctx context.Context, workspaceID, reviewID string) ([]identitymodel.IdentityAccessReviewItem, error) {
	return s.ListItemsWithinDataScope(ctx, workspaceID, reviewID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *Store) ListItemsWithinDataScope(ctx context.Context, workspaceID, reviewID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityAccessReviewItem, error) {
	predicates := []query.Predicate{query.Equal("review_id", reviewID)}
	if !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_access_review_items", "user_id"), scope))
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_access_review_items", workspaceID).
		Columns("id").Where(query.And(predicates...)).OrderBy(query.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity access review item identifiers: %w", err)
	}
	rows, err := s.backend.DB().QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]identitymodel.IdentityAccessReviewItem, 0, len(ids))
	for _, id := range ids {
		item, found, err := s.LoadItemWithinDataScope(ctx, s.backend.DB(), workspaceID, id, scope)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, item)
		}
	}
	return out, nil
}

func (s *Store) LoadItem(ctx context.Context, queryer Queryer, workspaceID, itemID string) (identitymodel.IdentityAccessReviewItem, bool, error) {
	return s.loadItem(ctx, queryer, workspaceID, itemID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *Store) LoadItemWithinDataScope(ctx context.Context, queryer Queryer, workspaceID, itemID string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewItem, bool, error) {
	return s.loadItem(ctx, queryer, workspaceID, itemID, scope)
}

func (s *Store) loadItem(ctx context.Context, queryer Queryer, workspaceID, itemID string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewItem, bool, error) {
	predicates := []query.Predicate{query.Equal("id", itemID)}
	if !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_access_review_items", "user_id"), scope))
	}
	statement, arguments, buildErr := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_access_review_items", workspaceID).
		Columns("id", "review_id", "user_id", "role_id", "role_key", "binding_key", "profile_id", "risk_level", "priority", "priority_reasons_json", "last_used_at", "status", "decision", "replacement_role_id", "expires_at", "reviewer_id", "reason", "decided_at", "version", "created_at", "updated_at").
		Where(query.And(predicates...)).Build()
	if buildErr != nil {
		return identitymodel.IdentityAccessReviewItem{}, false, buildErr
	}
	var item identitymodel.IdentityAccessReviewItem
	var riskLevel string
	var priorityReasonsJSON string
	var bindingKey, profileID, lastUsedAt, decision, replacementRoleID, expiresAt, reviewerID, reason, decidedAt sql.NullString
	err := queryer.QueryRowContext(ctx, statement, arguments...).Scan(
		&item.ID, &item.ReviewID, &item.UserID, &item.RoleID, &item.RoleKey, &bindingKey, &profileID,
		&riskLevel, &item.Priority, &priorityReasonsJSON, &lastUsedAt, &item.Status, &decision, &replacementRoleID, &expiresAt, &reviewerID, &reason, &decidedAt,
		&item.Version, &item.CreatedAt, &item.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityAccessReviewItem{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityAccessReviewItem{}, false, err
	}
	item.BindingKey, item.ProfileID = bindingKey.String, profileID.String
	if err := json.Unmarshal([]byte(priorityReasonsJSON), &item.PriorityReasons); err != nil {
		return identitymodel.IdentityAccessReviewItem{}, false, err
	}
	item.LastUsedAt = lastUsedAt.String
	item.RiskLevel, item.Decision = identitymodel.IdentityRoleRiskLevel(riskLevel), identitymodel.IdentityAccessReviewDecision(decision.String)
	item.ReplacementRoleID, item.ExpiresAt, item.ReviewerID, item.Reason, item.DecidedAt = replacementRoleID.String, expiresAt.String, reviewerID.String, reason.String, decidedAt.String
	return item, true, nil
}

func (s *Store) LoadReceipt(ctx context.Context, queryer Queryer, workspaceID, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	return s.loadReceipt(ctx, queryer, workspaceID, itemID, idempotencyKey, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *Store) loadReceipt(ctx context.Context, queryer Queryer, workspaceID, itemID, idempotencyKey string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	predicates := []query.Predicate{query.Equal("item_id", itemID), query.Equal("idempotency_key", idempotencyKey)}
	if !scope.Unrestricted {
		predicates = append(predicates, query.Exists("_identity_access_review_items", query.And(
			query.Equal("workspace_id", workspaceID),
			query.EqualExpressions(query.Column("id"), query.TableColumn("_identity_access_review_receipts", "item_id")),
			identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_access_review_items", "user_id"), scope),
		)))
	}
	statement, arguments, buildErr := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_access_review_receipts", workspaceID).
		Columns("result_json", "request_fingerprint").Where(query.And(predicates...)).Build()
	if buildErr != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, buildErr
	}
	var resultJSON, fingerprint string
	err := queryer.QueryRowContext(ctx, statement, arguments...).Scan(&resultJSON, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, err
	}
	var receipt identitymodel.IdentityAccessReviewDecisionReceipt
	if err := json.Unmarshal([]byte(resultJSON), &receipt); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, err
	}
	receipt.RequestFingerprint = fingerprint
	return receipt, true, nil
}

func (s *Store) LoadAssignment(ctx context.Context, queryer Queryer, workspaceID, userID, roleID string) (identitymodel.IdentityUserRoleAssignment, bool, error) {
	statement, arguments, buildErr := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).
		Columns("binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at").
		Where(query.And(query.Equal("user_id", userID), query.Equal("role_id", roleID))).Build()
	if buildErr != nil {
		return identitymodel.IdentityUserRoleAssignment{}, false, buildErr
	}
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: userID, RoleID: roleID}
	var bindingKey, profileID, validFrom, validUntil, grantedBy, grantReason, revokedBy, revokedAt, revokeReason, expiresAt sql.NullString
	err := queryer.QueryRowContext(ctx, statement, arguments...).Scan(
		&bindingKey, &profileID, &assignment.Source, &assignment.Status, &validFrom, &validUntil,
		&grantedBy, &grantReason, &revokedBy, &revokedAt, &revokeReason, &expiresAt, &assignment.CreatedAt, &assignment.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityUserRoleAssignment{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityUserRoleAssignment{}, false, err
	}
	assignment.BindingKey, assignment.ProfileID = bindingKey.String, profileID.String
	assignment.ValidFrom, assignment.ValidUntil, assignment.GrantedBy, assignment.GrantReason = validFrom.String, validUntil.String, grantedBy.String, grantReason.String
	assignment.RevokedBy, assignment.RevokedAt, assignment.RevokeReason, assignment.ExpiresAt = revokedBy.String, revokedAt.String, revokeReason.String, pointerFromNull(expiresAt)
	return assignment, true, nil
}

func (s *Store) LoadRole(ctx context.Context, queryer Queryer, workspaceID, roleID string) (identitymodel.IdentityRole, bool, error) {
	statement, arguments, buildErr := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_roles", workspaceID).
		Columns("id", "role_key", "label", "description", "status").Where(query.Equal("id", roleID)).Build()
	if buildErr != nil {
		return identitymodel.IdentityRole{}, false, buildErr
	}
	var role identitymodel.IdentityRole
	var status string
	err := queryer.QueryRowContext(ctx, statement, arguments...).Scan(&role.ID, &role.Key, &role.Label, &role.Description, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityRole{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityRole{}, false, err
	}
	role.Status = identitymodel.IdentityStatus(status)
	return role, true, nil
}

func identityWorkspaceID(value string) (string, error) {
	workspace, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return workspace.String(), nil
}

func identityID(parts ...string) string {
	value := strings.Join(parts, "_")
	return strings.NewReplacer(".", "_", ":", "_", "/", "_").Replace(value)
}

func nullIfBlank(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func pointerFromNull(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	out := value.String
	return &out
}
