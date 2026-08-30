package transferbatch

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
}

type ApplyLifecycle func(context.Context, *sql.Tx, string, identitymodel.IdentityWorkforceLifecycleMutation) (identitymodel.IdentityWorkforceLifecycleResult, error)

type Store struct {
	backend        Backend
	now            func() string
	applyLifecycle ApplyLifecycle
}

func New(backend Backend, now func() string, applyLifecycle ApplyLifecycle) Store {
	return Store{backend: backend, now: now, applyLifecycle: applyLifecycle}
}

func (s Store) GetReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityWorkforceTransferBatchReceipt, bool, error) {
	workspaceID, err := workspaceIdentifier(workspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, false, err
	}
	return s.loadReceipt(ctx, s.backend.DB(), workspaceID, strings.TrimSpace(idempotencyKey))
}

func (s Store) Apply(ctx context.Context, mutation identitymodel.IdentityWorkforceTransferBatchMutation) (identitymodel.IdentityWorkforceTransferBatchReceipt, error) {
	workspaceID, err := workspaceIdentifier(mutation.WorkspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
	}
	mutation.ActorID = strings.TrimSpace(mutation.ActorID)
	mutation.IdempotencyKey = strings.TrimSpace(mutation.IdempotencyKey)
	mutation.RequestFingerprint = strings.TrimSpace(mutation.RequestFingerprint)
	if mutation.ActorID == "" || mutation.IdempotencyKey == "" || mutation.RequestFingerprint == "" || len(mutation.Items) == 0 || len(mutation.Items) != len(mutation.Mutations) {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, fmt.Errorf("identity workforce transfer batch mutation is invalid")
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
	}
	defer tx.Rollback()
	if receipt, found, loadErr := s.loadReceipt(ctx, tx, workspaceID, mutation.IdempotencyKey); loadErr != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, loadErr
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.idempotency_key_reused"}
		}
		receipt.Replayed = true
		return receipt, nil
	}
	for _, lifecycle := range mutation.Mutations {
		if _, err := s.applyLifecycle(ctx, tx, workspaceID, lifecycle); err != nil {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
		}
	}
	receipt := identitymodel.IdentityWorkforceTransferBatchReceipt{
		ID:          identifier("identity_workforce_transfer_batch", workspaceID, mutation.IdempotencyKey),
		WorkspaceID: workspaceID, ActorID: mutation.ActorID, IdempotencyKey: mutation.IdempotencyKey,
		RequestFingerprint: mutation.RequestFingerprint, Items: mutation.Items, CreatedAt: s.now(),
	}
	// The receipt contains only strings and typed Workforce values, so it is
	// always JSON-encodable.
	resultJSON, _ := json.Marshal(receipt)
	statement, arguments, err := ormbuilder.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "identity_workforce_transfer_batch_receipts", workspaceID).
		Columns("id", "actor_id", "idempotency_key", "request_fingerprint", "result_json", "created_at").
		Values(receipt.ID, receipt.ActorID, receipt.IdempotencyKey, receipt.RequestFingerprint, string(resultJSON), receipt.CreatedAt).Build()
	if err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, fmt.Errorf("build identity workforce transfer batch receipt: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
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

func (s Store) loadReceipt(ctx context.Context, queryer identityWorkforceTransferBatchQueryer, workspaceID, idempotencyKey string) (identitymodel.IdentityWorkforceTransferBatchReceipt, bool, error) {
	statement, arguments, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "identity_workforce_transfer_batch_receipts", workspaceID).
		Columns("result_json", "request_fingerprint").Where(ormbuilder.Equal("idempotency_key", idempotencyKey)).Build()
	if buildErr != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, false, buildErr
	}
	var resultJSON, fingerprint string
	err := queryer.QueryRowContext(ctx, statement, arguments...).Scan(&resultJSON, &fingerprint)
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
