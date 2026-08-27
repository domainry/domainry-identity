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
)

type identityEntitlementReceiptQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SQLIdentityStore) GetIdentityEntitlementBatchReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	return s.loadIdentityEntitlementBatchReceipt(ctx, s.db, workspaceID, strings.TrimSpace(idempotencyKey))
}

func (s *SQLIdentityStore) ApplyIdentityEntitlementBatch(ctx context.Context, mutation identitymodel.IdentityEntitlementBatchMutation) (identitymodel.IdentityEntitlementBatchReceipt, error) {
	workspaceID, err := identityWorkspaceID(mutation.WorkspaceID)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	mutation.WorkspaceID = workspaceID
	mutation.ActorID = strings.TrimSpace(mutation.ActorID)
	mutation.IdempotencyKey = strings.TrimSpace(mutation.IdempotencyKey)
	mutation.RequestFingerprint = strings.TrimSpace(mutation.RequestFingerprint)
	if mutation.ActorID == "" || mutation.IdempotencyKey == "" || mutation.RequestFingerprint == "" || len(mutation.Items) == 0 || len(mutation.Items) != len(mutation.Assignments) {
		return identitymodel.IdentityEntitlementBatchReceipt{}, fmt.Errorf("identity entitlement batch mutation is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	defer tx.Rollback()
	if receipt, found, loadErr := s.loadIdentityEntitlementBatchReceipt(ctx, tx, workspaceID, mutation.IdempotencyKey); loadErr != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, loadErr
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityEntitlementBatchReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.idempotency_key_reused"}
		}
		receipt.Replayed = true
		return receipt, nil
	}
	if err := s.writeIdentityUserRoleAssignmentBatch(ctx, tx, workspaceID, mutation.Assignments); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	receipt := identitymodel.IdentityEntitlementBatchReceipt{
		ID:                 identityID("identity_entitlement_batch", workspaceID, mutation.IdempotencyKey),
		WorkspaceID:        workspaceID,
		ActorID:            mutation.ActorID,
		IdempotencyKey:     mutation.IdempotencyKey,
		RequestFingerprint: mutation.RequestFingerprint,
		Items:              mutation.Items,
		CreatedAt:          nowString(),
	}
	// The receipt contains only strings and typed entitlement values, so it is
	// always JSON-encodable.
	resultJSON, _ := json.Marshal(receipt)
	query := "INSERT INTO " + s.tableIdentifier("identity_entitlement_batch_receipts") + " (" +
		s.identityColumns("id", "workspace_id", "actor_id", "idempotency_key", "request_fingerprint", "result_json", "created_at") +
		") VALUES (" + s.placeholders(7) + ")"
	if _, err := tx.ExecContext(ctx, query, receipt.ID, receipt.WorkspaceID, receipt.ActorID, receipt.IdempotencyKey, receipt.RequestFingerprint, string(resultJSON), receipt.CreatedAt); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	return receipt, nil
}

const identityUserRoleAssignmentInsertBatchSize = 40
const identityUserRoleAssignmentDeleteBatchSize = 200

func (s *SQLIdentityStore) writeIdentityUserRoleAssignmentBatch(ctx context.Context, tx *sql.Tx, workspaceID string, assignments []identitymodel.IdentityUserRoleAssignment) error {
	normalized := make([]identitymodel.IdentityUserRoleAssignment, 0, len(assignments))
	positions := make(map[string]int, len(assignments))
	for _, assignment := range assignments {
		value, err := normalizeIdentityUserRoleAssignment(assignment)
		if err != nil {
			return err
		}
		key := value.UserID + "\x00" + value.RoleID
		if position, ok := positions[key]; ok {
			normalized[position] = value
			continue
		}
		positions[key] = len(normalized)
		normalized = append(normalized, value)
	}
	for start := 0; start < len(normalized); start += identityUserRoleAssignmentDeleteBatchSize {
		end := min(start+identityUserRoleAssignmentDeleteBatchSize, len(normalized))
		args := []any{workspaceID}
		pairs := make([]string, 0, end-start)
		for _, assignment := range normalized[start:end] {
			args = append(args, assignment.UserID, assignment.RoleID)
			pairs = append(pairs, "("+s.identifier("user_id")+" = "+s.placeholder(len(args)-1)+" AND "+s.identifier("role_id")+" = "+s.placeholder(len(args))+")")
		}
		query := "DELETE FROM " + s.tableIdentifier("identity_user_role_assignments") + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1) + " AND (" + strings.Join(pairs, " OR ") + ")"
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}
	now := nowString()
	for start := 0; start < len(normalized); start += identityUserRoleAssignmentInsertBatchSize {
		end := min(start+identityUserRoleAssignmentInsertBatchSize, len(normalized))
		args := make([]any, 0, (end-start)*len(identityUserRoleAssignmentColumns))
		rows := make([]string, 0, end-start)
		for _, assignment := range normalized[start:end] {
			values := identityUserRoleAssignmentValues(workspaceID, assignment, now)
			placeholders := make([]string, len(values))
			for index := range values {
				placeholders[index] = s.placeholder(len(args) + index + 1)
			}
			rows = append(rows, "("+strings.Join(placeholders, ", ")+")")
			args = append(args, values...)
		}
		query := "INSERT INTO " + s.tableIdentifier("identity_user_role_assignments") + " (" + s.identityColumns(identityUserRoleAssignmentColumns...) + ") VALUES " + strings.Join(rows, ", ")
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLIdentityStore) loadIdentityEntitlementBatchReceipt(ctx context.Context, queryer identityEntitlementReceiptQueryer, workspaceID, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	query := "SELECT " + s.identityColumns("result_json", "request_fingerprint") + " FROM " +
		s.tableIdentifier("identity_entitlement_batch_receipts") + " WHERE " +
		s.identifier("workspace_id") + " = " + s.placeholder(1) + " AND " +
		s.identifier("idempotency_key") + " = " + s.placeholder(2)
	var resultJSON, fingerprint string
	err := queryer.QueryRowContext(ctx, query, workspaceID, idempotencyKey).Scan(&resultJSON, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	var receipt identitymodel.IdentityEntitlementBatchReceipt
	if err := json.Unmarshal([]byte(resultJSON), &receipt); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	receipt.RequestFingerprint = fingerprint
	return receipt, true, nil
}
