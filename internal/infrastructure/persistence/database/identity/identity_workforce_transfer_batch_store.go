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

func (s *SQLIdentityStore) GetIdentityWorkforceTransferBatchReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityWorkforceTransferBatchReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, false, err
	}
	return s.loadIdentityWorkforceTransferBatchReceipt(ctx, s.db, workspaceID, strings.TrimSpace(idempotencyKey))
}

func (s *SQLIdentityStore) ApplyIdentityWorkforceTransferBatch(ctx context.Context, mutation identitymodel.IdentityWorkforceTransferBatchMutation) (identitymodel.IdentityWorkforceTransferBatchReceipt, error) {
	workspaceID, err := identityWorkspaceID(mutation.WorkspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
	}
	mutation.ActorID = strings.TrimSpace(mutation.ActorID)
	mutation.IdempotencyKey = strings.TrimSpace(mutation.IdempotencyKey)
	mutation.RequestFingerprint = strings.TrimSpace(mutation.RequestFingerprint)
	if mutation.ActorID == "" || mutation.IdempotencyKey == "" || mutation.RequestFingerprint == "" || len(mutation.Items) == 0 || len(mutation.Items) != len(mutation.Mutations) {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, fmt.Errorf("identity workforce transfer batch mutation is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
	}
	defer tx.Rollback()
	if receipt, found, loadErr := s.loadIdentityWorkforceTransferBatchReceipt(ctx, tx, workspaceID, mutation.IdempotencyKey); loadErr != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, loadErr
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.idempotency_key_reused"}
		}
		receipt.Replayed = true
		return receipt, nil
	}
	for _, lifecycle := range mutation.Mutations {
		if _, err := s.applyIdentityWorkforceLifecycleTx(ctx, tx, workspaceID, lifecycle); err != nil {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
		}
	}
	receipt := identitymodel.IdentityWorkforceTransferBatchReceipt{
		ID:          identityID("identity_workforce_transfer_batch", workspaceID, mutation.IdempotencyKey),
		WorkspaceID: workspaceID, ActorID: mutation.ActorID, IdempotencyKey: mutation.IdempotencyKey,
		RequestFingerprint: mutation.RequestFingerprint, Items: mutation.Items, CreatedAt: nowString(),
	}
	// The receipt contains only strings and typed Workforce values, so it is
	// always JSON-encodable.
	resultJSON, _ := json.Marshal(receipt)
	query := "INSERT INTO " + s.tableIdentifier("identity_workforce_transfer_batch_receipts") + " (" +
		s.identityColumns("id", "workspace_id", "actor_id", "idempotency_key", "request_fingerprint", "result_json", "created_at") +
		") VALUES (" + s.placeholders(7) + ")"
	if _, err := tx.ExecContext(ctx, query, receipt.ID, receipt.WorkspaceID, receipt.ActorID, receipt.IdempotencyKey, receipt.RequestFingerprint, string(resultJSON), receipt.CreatedAt); err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
	}
	return receipt, nil
}

type identityWorkforceTransferBatchQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SQLIdentityStore) loadIdentityWorkforceTransferBatchReceipt(ctx context.Context, queryer identityWorkforceTransferBatchQueryer, workspaceID, idempotencyKey string) (identitymodel.IdentityWorkforceTransferBatchReceipt, bool, error) {
	query := "SELECT " + s.identityColumns("result_json", "request_fingerprint") + " FROM " +
		s.tableIdentifier("identity_workforce_transfer_batch_receipts") + " WHERE " +
		s.identifier("workspace_id") + " = " + s.placeholder(1) + " AND " +
		s.identifier("idempotency_key") + " = " + s.placeholder(2)
	var resultJSON, fingerprint string
	err := queryer.QueryRowContext(ctx, query, workspaceID, idempotencyKey).Scan(&resultJSON, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, false, err
	}
	var receipt identitymodel.IdentityWorkforceTransferBatchReceipt
	if err := json.Unmarshal([]byte(resultJSON), &receipt); err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, false, err
	}
	receipt.RequestFingerprint = fingerprint
	return receipt, true, nil
}
