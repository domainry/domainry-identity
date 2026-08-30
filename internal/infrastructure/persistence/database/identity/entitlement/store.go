package entitlement

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
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

type identityEntitlementReceiptQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const AssignmentInsertBatchSize = roleassignmentpersistence.InsertBatchSize

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*ormbuilder.InsertBuilder, []string, ...string) *ormbuilder.InsertBuilder
}

type Store struct {
	backend Backend
	now     func() string
}

func New(backend Backend, now func() string) Store { return Store{backend: backend, now: now} }

func (s Store) GetReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	workspaceID, err := workspaceIdentifier(workspaceID)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	return s.loadReceipt(ctx, s.backend.DB(), workspaceID, strings.TrimSpace(idempotencyKey))
}

func (s Store) Apply(ctx context.Context, mutation identitymodel.IdentityEntitlementBatchMutation) (identitymodel.IdentityEntitlementBatchReceipt, error) {
	workspaceID, err := workspaceIdentifier(mutation.WorkspaceID)
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
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	defer tx.Rollback()
	if receipt, found, loadErr := s.loadReceipt(ctx, tx, workspaceID, mutation.IdempotencyKey); loadErr != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, loadErr
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityEntitlementBatchReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.idempotency_key_reused"}
		}
		receipt.Replayed = true
		return receipt, nil
	}
	if err := roleassignmentpersistence.New(s.backend, s.now).UpsertBatch(ctx, tx, workspaceID, mutation.Assignments); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	receipt := identitymodel.IdentityEntitlementBatchReceipt{
		ID:                 identifier("identity_entitlement_batch", workspaceID, mutation.IdempotencyKey),
		WorkspaceID:        workspaceID,
		ActorID:            mutation.ActorID,
		IdempotencyKey:     mutation.IdempotencyKey,
		RequestFingerprint: mutation.RequestFingerprint,
		Items:              mutation.Items,
		CreatedAt:          s.now(),
	}
	// The receipt contains only strings and typed entitlement values, so it is
	// always JSON-encodable.
	resultJSON, _ := json.Marshal(receipt)
	statement, arguments, err := ormbuilder.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "identity_entitlement_batch_receipts", workspaceID).
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

func (s Store) loadReceipt(ctx context.Context, queryer identityEntitlementReceiptQueryer, workspaceID, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	statement, arguments, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "identity_entitlement_batch_receipts", workspaceID).
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
