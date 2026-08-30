package authoring

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
}

// Repository persists the small mutation envelope required by
// Identity Admin. It deliberately does not expose the Runtime-wide Operations
// subsystem or its queues, diagnostics and control-plane contracts.
type Repository struct {
	store Backend
}

var _ identityauthoring.Repository = (*Repository)(nil)

func NewRepository(store Backend) *Repository {
	return &Repository{store: store}
}

func (r *Repository) Claim(ctx context.Context, candidate identityauthoring.Receipt, leaseTTL time.Duration) (identityauthoring.Claim, error) {
	if r == nil || r.store == nil {
		return identityauthoring.Claim{}, errors.New("identity authoring repository is unavailable")
	}
	columns := identityAuthoringReceiptColumns()
	values := identityAuthoringReceiptValues(candidate)
	statement, arguments, buildErr := ormbuilder.NewWorkspaceInsertBuilder(r.store.SQLRenderer(), "_identity_authoring_receipts", candidate.WorkspaceID).
		Columns(append([]string{columns[0]}, columns[2:]...)...).
		Values(append([]any{values[0]}, values[2:]...)...).Build()
	if buildErr != nil {
		return identityauthoring.Claim{}, fmt.Errorf("build identity authoring receipt insert: %w", buildErr)
	}
	_, insertErr := r.store.DB().ExecContext(ctx, statement, arguments...)
	if insertErr == nil {
		return identityauthoring.Claim{Decision: idempotency.DecisionAcquired, Receipt: candidate}, nil
	}
	current, found, err := r.findByKey(ctx, candidate.WorkspaceID, candidate.IdempotencyKey)
	if err != nil {
		return identityauthoring.Claim{}, err
	}
	if !found {
		return identityauthoring.Claim{}, fmt.Errorf("insert identity authoring receipt: %w", insertErr)
	}
	decision := idempotency.Classify(idempotency.ReceiptState{
		Status:      current.Status,
		Fingerprint: current.RequestFingerprint,
		Lease:       idempotency.Lease{Owner: current.LeaseOwner, Token: current.FencingToken, ExpiresAt: current.LeaseExpiresAt},
	}, candidate.RequestFingerprint, candidate.UpdatedAt)
	if decision != idempotency.DecisionAcquired {
		return identityauthoring.Claim{Decision: decision, Receipt: current}, nil
	}
	candidate.ID = current.ID
	candidate.CreatedAt = current.CreatedAt
	candidate.FencingToken = current.FencingToken + 1
	candidate.LeaseExpiresAt = candidate.UpdatedAt.Add(leaseTTL)
	statement, arguments, err = ormbuilder.NewWorkspaceUpdateBuilder(r.store.SQLRenderer(), "_identity_authoring_receipts", candidate.WorkspaceID).
		Set("status", string(idempotency.StatusProcessing)).Set("lease_owner", candidate.LeaseOwner).
		Set("lease_expires_at", formatAuthoringTime(candidate.LeaseExpiresAt)).Set("fencing_token", candidate.FencingToken).
		Set("updated_at", formatAuthoringTime(candidate.UpdatedAt)).
		Where(ormbuilder.And(ormbuilder.Equal("id", candidate.ID), ormbuilder.Equal("request_fingerprint", candidate.RequestFingerprint), ormbuilder.Equal("status", string(current.Status)), ormbuilder.Equal("fencing_token", current.FencingToken))).Build()
	if err != nil {
		return identityauthoring.Claim{}, fmt.Errorf("build identity authoring receipt claim: %w", err)
	}
	result, err := r.store.DB().ExecContext(ctx, statement, arguments...)
	if err != nil {
		return identityauthoring.Claim{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return identityauthoring.Claim{}, err
	}
	if rows == 1 {
		return identityauthoring.Claim{Decision: idempotency.DecisionAcquired, Receipt: candidate}, nil
	}
	current, found, err = r.findByKey(ctx, candidate.WorkspaceID, candidate.IdempotencyKey)
	if err != nil {
		return identityauthoring.Claim{}, err
	}
	if !found {
		return identityauthoring.Claim{}, identityauthoring.ErrReceiptUnavailable
	}
	return identityauthoring.Claim{Decision: idempotency.DecisionInProgress, Receipt: current}, nil
}

func (r *Repository) Complete(ctx context.Context, completion identityauthoring.Completion) (identityauthoring.Receipt, error) {
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(r.store.SQLRenderer(), "_identity_authoring_receipts", completion.WorkspaceID).
		Set("status", string(completion.Status)).Set("result_json", string(completion.Result)).Set("updated_at", formatAuthoringTime(completion.CompletedAt)).
		Where(ormbuilder.And(ormbuilder.Equal("id", completion.ReceiptID), ormbuilder.Equal("lease_owner", completion.LeaseOwner), ormbuilder.Equal("fencing_token", completion.FencingToken), ormbuilder.Equal("status", string(idempotency.StatusProcessing)))).Build()
	if err != nil {
		return identityauthoring.Receipt{}, fmt.Errorf("build identity authoring receipt completion: %w", err)
	}
	result, err := r.store.DB().ExecContext(ctx, statement, arguments...)
	if err != nil {
		return identityauthoring.Receipt{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return identityauthoring.Receipt{}, err
	}
	if rows != 1 {
		return identityauthoring.Receipt{}, identityauthoring.ErrLeaseLost
	}
	return r.findByID(ctx, completion.WorkspaceID, completion.ReceiptID)
}

func (r *Repository) findByKey(ctx context.Context, workspaceID, key string) (identityauthoring.Receipt, bool, error) {
	statement, arguments, buildErr := ormbuilder.NewWorkspaceSelectBuilder(r.store.SQLRenderer(), "_identity_authoring_receipts", workspaceID).
		Columns(identityAuthoringReceiptColumns()...).Where(ormbuilder.Equal("idempotency_key", key)).Build()
	if buildErr != nil {
		return identityauthoring.Receipt{}, false, buildErr
	}
	receipt, err := scanIdentityAuthoringReceipt(r.store.DB().QueryRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return identityauthoring.Receipt{}, false, nil
	}
	return receipt, err == nil, err
}

func (r *Repository) findByID(ctx context.Context, workspaceID, id string) (identityauthoring.Receipt, error) {
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(r.store.SQLRenderer(), "_identity_authoring_receipts", workspaceID).
		Columns(identityAuthoringReceiptColumns()...).Where(ormbuilder.Equal("id", id)).Build()
	if err != nil {
		return identityauthoring.Receipt{}, err
	}
	return scanIdentityAuthoringReceipt(r.store.DB().QueryRowContext(ctx, statement, arguments...))
}

func identityAuthoringReceiptColumns() []string {
	return []string{"id", "workspace_id", "use_case", "resource_type", "target_id", "idempotency_key", "request_fingerprint", "status", "result_json", "lease_owner", "lease_expires_at", "fencing_token", "created_at", "updated_at"}
}

func identityAuthoringReceiptValues(value identityauthoring.Receipt) []any {
	return []any{value.ID, value.WorkspaceID, value.UseCase, value.ResourceType, value.TargetID, value.IdempotencyKey, value.RequestFingerprint, string(value.Status), string(value.Result), value.LeaseOwner, formatAuthoringTime(value.LeaseExpiresAt), value.FencingToken, formatAuthoringTime(value.CreatedAt), formatAuthoringTime(value.UpdatedAt)}
}

type identityAuthoringScanner interface{ Scan(...any) error }

func scanIdentityAuthoringReceipt(row identityAuthoringScanner) (identityauthoring.Receipt, error) {
	var value identityauthoring.Receipt
	var status, resultJSON, leaseExpiresAt, createdAt, updatedAt string
	err := row.Scan(&value.ID, &value.WorkspaceID, &value.UseCase, &value.ResourceType, &value.TargetID, &value.IdempotencyKey, &value.RequestFingerprint, &status, &resultJSON, &value.LeaseOwner, &leaseExpiresAt, &value.FencingToken, &createdAt, &updatedAt)
	value.Status = idempotency.Status(status)
	value.Result = []byte(resultJSON)
	value.LeaseExpiresAt, _ = time.Parse(time.RFC3339Nano, leaseExpiresAt)
	value.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	value.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return value, err
}

func formatAuthoringTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
