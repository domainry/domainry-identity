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
	roleassignmentpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/roleassignment"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

type identityEntitlementReceiptQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const identityUserRoleAssignmentInsertBatchSize = roleassignmentpersistence.InsertBatchSize

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
	statement, arguments, err := ormbuilder.NewWorkspaceInsertBuilder(s.sqlRenderer(), "identity_entitlement_batch_receipts", workspaceID).
		Columns("id", "actor_id", "idempotency_key", "request_fingerprint", "result_json", "created_at").
		Values(receipt.ID, receipt.ActorID, receipt.IdempotencyKey, receipt.RequestFingerprint, string(resultJSON), receipt.CreatedAt).Build()
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, fmt.Errorf("build identity entitlement batch receipt: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	return receipt, nil
}

func (s *SQLIdentityStore) writeIdentityUserRoleAssignmentBatch(ctx context.Context, tx *sql.Tx, workspaceID string, assignments []identitymodel.IdentityUserRoleAssignment) error {
	return roleassignmentpersistence.New(s, nowString).UpsertBatch(ctx, tx, workspaceID, assignments)
}

func (s *SQLIdentityStore) loadIdentityEntitlementBatchReceipt(ctx context.Context, queryer identityEntitlementReceiptQueryer, workspaceID, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	statement, arguments, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_entitlement_batch_receipts", workspaceID).
		Columns("result_json", "request_fingerprint").Where(ormbuilder.Equal("idempotency_key", idempotencyKey)).Build()
	if buildErr != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, buildErr
	}
	var resultJSON, fingerprint string
	err := queryer.QueryRowContext(ctx, statement, arguments...).Scan(&resultJSON, &fingerprint)
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
