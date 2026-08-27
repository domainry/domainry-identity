package identity

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
)

var _ identityrepository.IdentityAccessReviewRepository = (*SQLIdentityStore)(nil)

type identityAccessReviewQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SQLIdentityStore) CreateIdentityAccessReview(ctx context.Context, review identitymodel.IdentityAccessReview) error {
	workspaceID, err := identityWorkspaceID(review.WorkspaceID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(review.ID) == "" || strings.TrimSpace(review.CreatedBy) == "" || len(review.Items) == 0 {
		return fmt.Errorf("identity access review is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := "INSERT INTO " + s.tableIdentifier("identity_access_reviews") + " (" +
		s.identityColumns("id", "workspace_id", "period_start", "period_end", "due_at", "status", "created_by", "created_at", "updated_at") +
		") VALUES (" + s.placeholders(9) + ")"
	if _, err := tx.ExecContext(ctx, query, review.ID, workspaceID, review.PeriodStart, review.PeriodEnd, review.DueAt, review.Status, review.CreatedBy, review.CreatedAt, review.UpdatedAt); err != nil {
		return err
	}
	for _, item := range review.Items {
		// Priority reasons are strings, so this concrete JSON encoding cannot fail.
		priorityReasonsJSON, _ := json.Marshal(item.PriorityReasons)
		query = "INSERT INTO " + s.tableIdentifier("identity_access_review_items") + " (" +
			s.identityColumns("id", "workspace_id", "review_id", "user_id", "role_id", "role_key", "workforce_profile_id", "binding_key", "profile_id", "risk_level", "priority", "priority_reasons_json", "last_used_at", "status", "decision", "replacement_role_id", "expires_at", "reviewer_id", "reason", "decided_at", "version", "created_at", "updated_at") +
			") VALUES (" + s.placeholders(23) + ")"
		if _, err := tx.ExecContext(ctx, query,
			item.ID, workspaceID, review.ID, item.UserID, item.RoleID, item.RoleKey,
			nullIfBlank(item.WorkforceProfileID), nullIfBlank(item.BindingKey), nullIfBlank(item.ProfileID),
			item.RiskLevel, item.Priority, string(priorityReasonsJSON), nullIfBlank(item.LastUsedAt),
			item.Status, nullIfBlank(string(item.Decision)), nullIfBlank(item.ReplacementRoleID),
			nullIfBlank(item.ExpiresAt), nullIfBlank(item.ReviewerID), nullIfBlank(item.Reason), nullIfBlank(item.DecidedAt),
			item.Version, item.CreatedAt, item.UpdatedAt,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLIdentityStore) ListIdentityAccessReviews(ctx context.Context, workspaceID, status string) ([]identitymodel.IdentityAccessReview, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	query := "SELECT " + s.identityColumns("id", "period_start", "period_end", "due_at", "status", "created_by", "created_at", "updated_at") +
		" FROM " + s.tableIdentifier("identity_access_reviews") + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1)
	args := []any{workspaceID}
	if status = strings.TrimSpace(status); status != "" {
		query += " AND " + s.identifier("status") + " = " + s.placeholder(2)
		args = append(args, status)
	}
	query += " ORDER BY " + s.identifier("created_at") + " DESC, " + s.identifier("id")
	rows, err := s.db.QueryContext(ctx, query, args...)
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
		items, err := s.listIdentityAccessReviewItems(ctx, workspaceID, out[index].ID)
		if err != nil {
			return nil, err
		}
		out[index].Items = items
	}
	return out, nil
}

func (s *SQLIdentityStore) GetIdentityAccessReviewItem(ctx context.Context, workspaceID, itemID string) (identitymodel.IdentityAccessReviewItem, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityAccessReviewItem{}, false, err
	}
	return s.loadIdentityAccessReviewItem(ctx, s.db, workspaceID, strings.TrimSpace(itemID))
}

func (s *SQLIdentityStore) GetIdentityAccessReviewDecisionReceipt(ctx context.Context, workspaceID, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, err
	}
	return s.loadIdentityAccessReviewReceipt(ctx, s.db, workspaceID, strings.TrimSpace(itemID), strings.TrimSpace(idempotencyKey))
}

func (s *SQLIdentityStore) ApplyIdentityAccessReviewDecision(ctx context.Context, mutation identitymodel.IdentityAccessReviewDecisionMutation) (identitymodel.IdentityAccessReviewDecisionReceipt, error) {
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	defer tx.Rollback()
	if receipt, found, err := s.loadIdentityAccessReviewReceipt(ctx, tx, workspaceID, mutation.ItemID, mutation.Request.IdempotencyKey); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.idempotency_key_reused"}
		}
		receipt.Replayed = true
		return receipt, nil
	}
	item, found, err := s.loadIdentityAccessReviewItem(ctx, tx, workspaceID, mutation.ItemID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	if !found {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.access_review_item_not_found"}
	}
	if item.Status != "pending" || item.Version != mutation.Request.ExpectedVersion {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.access_review_concurrent_decision"}
	}
	assignment, assignmentFound, err := s.loadIdentityAccessReviewAssignment(ctx, tx, workspaceID, item.UserID, item.RoleID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	now := nowString()
	switch mutation.Request.Decision {
	case identitymodel.IdentityAccessReviewKeep:
	case identitymodel.IdentityAccessReviewRevoke:
		if assignmentFound {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_user_role_assignments")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("user_id")+" = "+s.placeholder(2)+" AND "+s.identifier("role_id")+" = "+s.placeholder(3), workspaceID, item.UserID, item.RoleID); err != nil {
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
		if _, found, err := s.loadIdentityAccessReviewRole(ctx, tx, workspaceID, replacement); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		} else if !found {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.role_not_found"}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_user_role_assignments")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("user_id")+" = "+s.placeholder(2)+" AND "+s.identifier("role_id")+" = "+s.placeholder(3), workspaceID, item.UserID, item.RoleID); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
		assignment.RoleID, assignment.Source, assignment.GrantedBy, assignment.GrantReason = replacement, "access_review", mutation.ReviewerID, mutation.Request.Reason
		assignment.CreatedAt, assignment.UpdatedAt = now, now
		if err := s.writeIdentityUserRoleAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
	case identitymodel.IdentityAccessReviewSetExpiry:
		if !assignmentFound {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.access_review_assignment_missing"}
		}
		expiresAt := strings.TrimSpace(mutation.Request.ExpiresAt)
		assignment.ExpiresAt, assignment.ValidUntil = &expiresAt, expiresAt
		assignment.Source, assignment.GrantedBy, assignment.GrantReason = "access_review", mutation.ReviewerID, mutation.Request.Reason
		if err := s.writeIdentityUserRoleAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
	default:
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.access_review_decision_invalid"}
	}
	item.Status, item.Decision, item.ReplacementRoleID, item.ExpiresAt = "decided", mutation.Request.Decision, strings.TrimSpace(mutation.Request.ReplacementRoleID), strings.TrimSpace(mutation.Request.ExpiresAt)
	item.ReviewerID, item.Reason, item.DecidedAt, item.UpdatedAt, item.Version = mutation.ReviewerID, strings.TrimSpace(mutation.Request.Reason), now, now, item.Version+1
	update := "UPDATE " + s.tableIdentifier("identity_access_review_items") + " SET " +
		s.identifier("status") + " = " + s.placeholder(1) + ", " + s.identifier("decision") + " = " + s.placeholder(2) + ", " +
		s.identifier("replacement_role_id") + " = " + s.placeholder(3) + ", " + s.identifier("expires_at") + " = " + s.placeholder(4) + ", " +
		s.identifier("reviewer_id") + " = " + s.placeholder(5) + ", " + s.identifier("reason") + " = " + s.placeholder(6) + ", " +
		s.identifier("decided_at") + " = " + s.placeholder(7) + ", " + s.identifier("updated_at") + " = " + s.placeholder(8) + ", " +
		s.identifier("version") + " = " + s.placeholder(9) + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(10) +
		" AND " + s.identifier("id") + " = " + s.placeholder(11) + " AND " + s.identifier("status") + " = " + s.placeholder(12) +
		" AND " + s.identifier("version") + " = " + s.placeholder(13)
	result, err := tx.ExecContext(ctx, update, item.Status, item.Decision, nullIfBlank(item.ReplacementRoleID), nullIfBlank(item.ExpiresAt), item.ReviewerID, item.Reason, item.DecidedAt, item.UpdatedAt, item.Version, workspaceID, item.ID, "pending", mutation.Request.ExpectedVersion)
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
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.tableIdentifier("identity_access_review_items")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("review_id")+" = "+s.placeholder(2)+" AND "+s.identifier("status")+" = "+s.placeholder(3), workspaceID, item.ReviewID, "pending").Scan(&pending); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	reviewStatus := identitymodel.IdentityAccessReviewOpen
	if pending == 0 {
		reviewStatus = identitymodel.IdentityAccessReviewCompleted
	}
	if _, err := tx.ExecContext(ctx, "UPDATE "+s.tableIdentifier("identity_access_reviews")+" SET "+s.identifier("status")+" = "+s.placeholder(1)+", "+s.identifier("updated_at")+" = "+s.placeholder(2)+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(3)+" AND "+s.identifier("id")+" = "+s.placeholder(4), reviewStatus, now, workspaceID, item.ReviewID); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	receipt := identitymodel.IdentityAccessReviewDecisionReceipt{
		ID:          identityID("identity_access_review_receipt", workspaceID, item.ID, mutation.Request.IdempotencyKey),
		WorkspaceID: workspaceID, ItemID: item.ID, IdempotencyKey: mutation.Request.IdempotencyKey,
		RequestFingerprint: mutation.RequestFingerprint, Item: item, CreatedAt: now,
	}
	// The receipt is composed only of JSON-safe concrete fields.
	resultJSON, _ := json.Marshal(receipt)
	insert := "INSERT INTO " + s.tableIdentifier("identity_access_review_receipts") + " (" +
		s.identityColumns("id", "workspace_id", "item_id", "idempotency_key", "request_fingerprint", "result_json", "created_at") +
		") VALUES (" + s.placeholders(7) + ")"
	if _, err := tx.ExecContext(ctx, insert, receipt.ID, workspaceID, item.ID, receipt.IdempotencyKey, receipt.RequestFingerprint, string(resultJSON), receipt.CreatedAt); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	return receipt, nil
}

func (s *SQLIdentityStore) listIdentityAccessReviewItems(ctx context.Context, workspaceID, reviewID string) ([]identitymodel.IdentityAccessReviewItem, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+s.identityColumns("id")+" FROM "+s.tableIdentifier("identity_access_review_items")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("review_id")+" = "+s.placeholder(2)+" ORDER BY "+s.identifier("id"), workspaceID, reviewID)
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
		item, found, err := s.loadIdentityAccessReviewItem(ctx, s.db, workspaceID, id)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, item)
		}
	}
	return out, nil
}

func (s *SQLIdentityStore) loadIdentityAccessReviewItem(ctx context.Context, queryer identityAccessReviewQueryer, workspaceID, itemID string) (identitymodel.IdentityAccessReviewItem, bool, error) {
	query := "SELECT " + s.identityColumns("id", "review_id", "user_id", "role_id", "role_key", "workforce_profile_id", "binding_key", "profile_id", "risk_level", "priority", "priority_reasons_json", "last_used_at", "status", "decision", "replacement_role_id", "expires_at", "reviewer_id", "reason", "decided_at", "version", "created_at", "updated_at") +
		" FROM " + s.tableIdentifier("identity_access_review_items") + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1) + " AND " + s.identifier("id") + " = " + s.placeholder(2)
	var item identitymodel.IdentityAccessReviewItem
	var riskLevel string
	var priorityReasonsJSON string
	var workforceProfileID, bindingKey, profileID, lastUsedAt, decision, replacementRoleID, expiresAt, reviewerID, reason, decidedAt sql.NullString
	err := queryer.QueryRowContext(ctx, query, workspaceID, itemID).Scan(
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

func (s *SQLIdentityStore) loadIdentityAccessReviewReceipt(ctx context.Context, queryer identityAccessReviewQueryer, workspaceID, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	query := "SELECT " + s.identityColumns("result_json", "request_fingerprint") + " FROM " + s.tableIdentifier("identity_access_review_receipts") +
		" WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1) + " AND " + s.identifier("item_id") + " = " + s.placeholder(2) + " AND " + s.identifier("idempotency_key") + " = " + s.placeholder(3)
	var resultJSON, fingerprint string
	err := queryer.QueryRowContext(ctx, query, workspaceID, itemID, idempotencyKey).Scan(&resultJSON, &fingerprint)
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

func (s *SQLIdentityStore) loadIdentityAccessReviewAssignment(ctx context.Context, queryer identityAccessReviewQueryer, workspaceID, userID, roleID string) (identitymodel.IdentityUserRoleAssignment, bool, error) {
	query := "SELECT " + s.identityColumns("workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at") +
		" FROM " + s.tableIdentifier("identity_user_role_assignments") + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1) + " AND " + s.identifier("user_id") + " = " + s.placeholder(2) + " AND " + s.identifier("role_id") + " = " + s.placeholder(3)
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: userID, RoleID: roleID}
	var workforceProfileID, bindingKey, profileID, validFrom, validUntil, grantedBy, grantReason, revokedBy, revokedAt, revokeReason, expiresAt sql.NullString
	err := queryer.QueryRowContext(ctx, query, workspaceID, userID, roleID).Scan(
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

func (s *SQLIdentityStore) loadIdentityAccessReviewRole(ctx context.Context, queryer identityAccessReviewQueryer, workspaceID, roleID string) (identitymodel.IdentityRole, bool, error) {
	query := "SELECT " + s.identityColumns("id", "role_key", "label", "description", "status") + " FROM " + s.tableIdentifier("identity_roles") +
		" WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1) + " AND " + s.identifier("id") + " = " + s.placeholder(2)
	var role identitymodel.IdentityRole
	var status string
	err := queryer.QueryRowContext(ctx, query, workspaceID, roleID).Scan(&role.ID, &role.Key, &role.Label, &role.Description, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityRole{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityRole{}, false, err
	}
	role.Status = identitymodel.IdentityStatus(status)
	return role, true, nil
}
