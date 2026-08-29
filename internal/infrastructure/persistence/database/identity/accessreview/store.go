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
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

var _ identityrepository.IdentityAccessReviewRepository = (*Store)(nil)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
}

type RoleAssignmentWriter func(context.Context, *sql.Tx, string, identitymodel.IdentityUserRoleAssignment) error

type Store struct {
	backend             Backend
	writeRoleAssignment RoleAssignmentWriter
	now                 func() string
}

func New(backend Backend, now func() string, writeRoleAssignment RoleAssignmentWriter) *Store {
	return &Store{backend: backend, now: now, writeRoleAssignment: writeRoleAssignment}
}

type Queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
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
	statement, arguments, err := ormbuilder.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "identity_access_reviews", workspaceID).
		Columns("id", "period_start", "period_end", "due_at", "status", "created_by", "created_at", "updated_at").
		Values(review.ID, review.PeriodStart, review.PeriodEnd, review.DueAt, review.Status, review.CreatedBy, review.CreatedAt, review.UpdatedAt).Build()
	if err != nil {
		return fmt.Errorf("build identity access review insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	items := ormbuilder.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "identity_access_review_items", workspaceID).
		Columns("id", "review_id", "user_id", "role_id", "role_key", "workforce_profile_id", "binding_key", "profile_id", "risk_level", "priority", "priority_reasons_json", "last_used_at", "status", "decision", "replacement_role_id", "expires_at", "reviewer_id", "reason", "decided_at", "version", "created_at", "updated_at")
	for _, item := range review.Items {
		// Priority reasons are strings, so this concrete JSON encoding cannot fail.
		priorityReasonsJSON, _ := json.Marshal(item.PriorityReasons)
		items.Values(
			item.ID, review.ID, item.UserID, item.RoleID, item.RoleKey,
			nullIfBlank(item.WorkforceProfileID), nullIfBlank(item.BindingKey), nullIfBlank(item.ProfileID),
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

func (s *Store) ListIdentityAccessReviews(ctx context.Context, workspaceID, status string) ([]identitymodel.IdentityAccessReview, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "identity_access_reviews", workspaceID).
		Columns("id", "period_start", "period_end", "due_at", "status", "created_by", "created_at", "updated_at").
		OrderBy(ormbuilder.Descending("created_at"), ormbuilder.Ascending("id"))
	if status = strings.TrimSpace(status); status != "" {
		builder.Where(ormbuilder.Equal("status", status))
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
		items, err := s.ListItems(ctx, workspaceID, out[index].ID)
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

func (s *Store) GetIdentityAccessReviewDecisionReceipt(ctx context.Context, workspaceID, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, err
	}
	return s.LoadReceipt(ctx, s.backend.DB(), workspaceID, strings.TrimSpace(itemID), strings.TrimSpace(idempotencyKey))
}

func (s *Store) ApplyIdentityAccessReviewDecision(ctx context.Context, mutation identitymodel.IdentityAccessReviewDecisionMutation) (identitymodel.IdentityAccessReviewDecisionReceipt, error) {
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
	if receipt, found, err := s.LoadReceipt(ctx, tx, workspaceID, mutation.ItemID, mutation.Request.IdempotencyKey); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.idempotency_key_reused"}
		}
		receipt.Replayed = true
		return receipt, nil
	}
	item, found, err := s.LoadItem(ctx, tx, workspaceID, mutation.ItemID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	if !found {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.access_review_item_not_found"}
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
			if err := s.deleteIdentityAccessReviewAssignment(ctx, tx, workspaceID, item.UserID, item.RoleID); err != nil {
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
		if err := s.deleteIdentityAccessReviewAssignment(ctx, tx, workspaceID, item.UserID, item.RoleID); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
		assignment.RoleID, assignment.Source, assignment.GrantedBy, assignment.GrantReason = replacement, "access_review", mutation.ReviewerID, mutation.Request.Reason
		assignment.CreatedAt, assignment.UpdatedAt = now, now
		if err := s.writeRoleAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
	case identitymodel.IdentityAccessReviewSetExpiry:
		if !assignmentFound {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.access_review_assignment_missing"}
		}
		expiresAt := strings.TrimSpace(mutation.Request.ExpiresAt)
		assignment.ExpiresAt, assignment.ValidUntil = &expiresAt, expiresAt
		assignment.Source, assignment.GrantedBy, assignment.GrantReason = "access_review", mutation.ReviewerID, mutation.Request.Reason
		if err := s.writeRoleAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
	default:
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.access_review_decision_invalid"}
	}
	item.Status, item.Decision, item.ReplacementRoleID, item.ExpiresAt = "decided", mutation.Request.Decision, strings.TrimSpace(mutation.Request.ReplacementRoleID), strings.TrimSpace(mutation.Request.ExpiresAt)
	item.ReviewerID, item.Reason, item.DecidedAt, item.UpdatedAt, item.Version = mutation.ReviewerID, strings.TrimSpace(mutation.Request.Reason), now, now, item.Version+1
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "identity_access_review_items", workspaceID).
		Set("status", item.Status).Set("decision", item.Decision).Set("replacement_role_id", nullIfBlank(item.ReplacementRoleID)).
		Set("expires_at", nullIfBlank(item.ExpiresAt)).Set("reviewer_id", item.ReviewerID).Set("reason", item.Reason).
		Set("decided_at", item.DecidedAt).Set("updated_at", item.UpdatedAt).Set("version", item.Version).
		Where(ormbuilder.And(ormbuilder.Equal("id", item.ID), ormbuilder.Equal("status", "pending"), ormbuilder.Equal("version", mutation.Request.ExpectedVersion))).Build()
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
	statement, arguments, err = ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "identity_access_review_items", workspaceID).
		Projections(ormbuilder.Project(ormbuilder.CountAll())).Where(ormbuilder.And(ormbuilder.Equal("review_id", item.ReviewID), ormbuilder.Equal("status", "pending"))).Build()
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
	statement, arguments, err = ormbuilder.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "identity_access_reviews", workspaceID).
		Set("status", reviewStatus).Set("updated_at", now).Where(ormbuilder.Equal("id", item.ReviewID)).Build()
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
	// The receipt is composed only of JSON-safe concrete fields.
	resultJSON, _ := json.Marshal(receipt)
	statement, arguments, err = ormbuilder.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "identity_access_review_receipts", workspaceID).
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

func (s *Store) deleteIdentityAccessReviewAssignment(ctx context.Context, tx *sql.Tx, workspaceID, userID, roleID string) error {
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), "identity_user_role_assignments", workspaceID).
		Where(ormbuilder.And(ormbuilder.Equal("user_id", userID), ormbuilder.Equal("role_id", roleID))).Build()
	if err != nil {
		return fmt.Errorf("build identity access review assignment delete: %w", err)
	}
	_, err = tx.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) ListItems(ctx context.Context, workspaceID, reviewID string) ([]identitymodel.IdentityAccessReviewItem, error) {
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "identity_access_review_items", workspaceID).
		Columns("id").Where(ormbuilder.Equal("review_id", reviewID)).OrderBy(ormbuilder.Ascending("id")).Build()
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
		item, found, err := s.LoadItem(ctx, s.backend.DB(), workspaceID, id)
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
	statement, arguments, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "identity_access_review_items", workspaceID).
		Columns("id", "review_id", "user_id", "role_id", "role_key", "workforce_profile_id", "binding_key", "profile_id", "risk_level", "priority", "priority_reasons_json", "last_used_at", "status", "decision", "replacement_role_id", "expires_at", "reviewer_id", "reason", "decided_at", "version", "created_at", "updated_at").
		Where(ormbuilder.Equal("id", itemID)).Build()
	if buildErr != nil {
		return identitymodel.IdentityAccessReviewItem{}, false, buildErr
	}
	var item identitymodel.IdentityAccessReviewItem
	var riskLevel string
	var priorityReasonsJSON string
	var workforceProfileID, bindingKey, profileID, lastUsedAt, decision, replacementRoleID, expiresAt, reviewerID, reason, decidedAt sql.NullString
	err := queryer.QueryRowContext(ctx, statement, arguments...).Scan(
		&item.ID, &item.ReviewID, &item.UserID, &item.RoleID, &item.RoleKey, &workforceProfileID, &bindingKey, &profileID,
		&riskLevel, &item.Priority, &priorityReasonsJSON, &lastUsedAt, &item.Status, &decision, &replacementRoleID, &expiresAt, &reviewerID, &reason, &decidedAt,
		&item.Version, &item.CreatedAt, &item.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityAccessReviewItem{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityAccessReviewItem{}, false, err
	}
	item.WorkforceProfileID, item.BindingKey, item.ProfileID = workforceProfileID.String, bindingKey.String, profileID.String
	if err := json.Unmarshal([]byte(priorityReasonsJSON), &item.PriorityReasons); err != nil {
		return identitymodel.IdentityAccessReviewItem{}, false, err
	}
	item.LastUsedAt = lastUsedAt.String
	item.RiskLevel, item.Decision = identitymodel.IdentityRoleRiskLevel(riskLevel), identitymodel.IdentityAccessReviewDecision(decision.String)
	item.ReplacementRoleID, item.ExpiresAt, item.ReviewerID, item.Reason, item.DecidedAt = replacementRoleID.String, expiresAt.String, reviewerID.String, reason.String, decidedAt.String
	return item, true, nil
}

func (s *Store) LoadReceipt(ctx context.Context, queryer Queryer, workspaceID, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	statement, arguments, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "identity_access_review_receipts", workspaceID).
		Columns("result_json", "request_fingerprint").Where(ormbuilder.And(ormbuilder.Equal("item_id", itemID), ormbuilder.Equal("idempotency_key", idempotencyKey))).Build()
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
	statement, arguments, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "identity_user_role_assignments", workspaceID).
		Columns("workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at").
		Where(ormbuilder.And(ormbuilder.Equal("user_id", userID), ormbuilder.Equal("role_id", roleID))).Build()
	if buildErr != nil {
		return identitymodel.IdentityUserRoleAssignment{}, false, buildErr
	}
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: userID, RoleID: roleID}
	var workforceProfileID, bindingKey, profileID, validFrom, validUntil, grantedBy, grantReason, revokedBy, revokedAt, revokeReason, expiresAt sql.NullString
	err := queryer.QueryRowContext(ctx, statement, arguments...).Scan(
		&workforceProfileID, &bindingKey, &profileID, &assignment.Source, &assignment.Status, &validFrom, &validUntil,
		&grantedBy, &grantReason, &revokedBy, &revokedAt, &revokeReason, &expiresAt, &assignment.CreatedAt, &assignment.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityUserRoleAssignment{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityUserRoleAssignment{}, false, err
	}
	assignment.WorkforceProfileID, assignment.BindingKey, assignment.ProfileID = workforceProfileID.String, bindingKey.String, profileID.String
	assignment.ValidFrom, assignment.ValidUntil, assignment.GrantedBy, assignment.GrantReason = validFrom.String, validUntil.String, grantedBy.String, grantReason.String
	assignment.RevokedBy, assignment.RevokedAt, assignment.RevokeReason, assignment.ExpiresAt = revokedBy.String, revokedAt.String, revokeReason.String, pointerFromNull(expiresAt)
	return assignment, true, nil
}

func (s *Store) LoadRole(ctx context.Context, queryer Queryer, workspaceID, roleID string) (identitymodel.IdentityRole, bool, error) {
	statement, arguments, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "identity_roles", workspaceID).
		Columns("id", "role_key", "label", "description", "status").Where(ormbuilder.Equal("id", roleID)).Build()
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
