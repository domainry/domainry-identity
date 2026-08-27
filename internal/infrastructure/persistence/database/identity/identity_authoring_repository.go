package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
)

// IdentityAuthoringRepository persists the small mutation envelope required by
// Identity Admin. It deliberately does not expose the Runtime-wide Operations
// subsystem or its queues, diagnostics and control-plane contracts.
type IdentityAuthoringRepository struct {
	store *SQLIdentityStore
}

var _ identityauthoring.Repository = (*IdentityAuthoringRepository)(nil)

func NewIdentityAuthoringRepository(store *SQLIdentityStore) *IdentityAuthoringRepository {
	return &IdentityAuthoringRepository{store: store}
}

func (r *IdentityAuthoringRepository) Claim(ctx context.Context, candidate identityauthoring.Receipt, leaseTTL time.Duration) (identityauthoring.Claim, error) {
	if r == nil || r.store == nil {
		return identityauthoring.Claim{}, errors.New("identity authoring repository is unavailable")
	}
	columns := identityAuthoringReceiptColumns()
	_, insertErr := r.store.DB().ExecContext(
		ctx,
		"INSERT INTO "+r.store.TableIdentifier("identity_authoring_receipts")+" ("+r.store.IdentityColumns(columns...)+") VALUES ("+r.store.Placeholders(len(columns))+")",
		identityAuthoringReceiptValues(candidate)...,
	)
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
	query := "UPDATE " + r.store.TableIdentifier("identity_authoring_receipts") + " SET " +
		r.store.Identifier("status") + " = " + r.store.Placeholder(1) + ", " +
		r.store.Identifier("lease_owner") + " = " + r.store.Placeholder(2) + ", " +
		r.store.Identifier("lease_expires_at") + " = " + r.store.Placeholder(3) + ", " +
		r.store.Identifier("fencing_token") + " = " + r.store.Placeholder(4) + ", " +
		r.store.Identifier("updated_at") + " = " + r.store.Placeholder(5) +
		" WHERE " + r.store.Identifier("workspace_id") + " = " + r.store.Placeholder(6) +
		" AND " + r.store.Identifier("id") + " = " + r.store.Placeholder(7) +
		" AND " + r.store.Identifier("request_fingerprint") + " = " + r.store.Placeholder(8) +
		" AND " + r.store.Identifier("status") + " = " + r.store.Placeholder(9) +
		" AND " + r.store.Identifier("fencing_token") + " = " + r.store.Placeholder(10)
	result, err := r.store.DB().ExecContext(ctx, query,
		string(idempotency.StatusProcessing), candidate.LeaseOwner, formatAuthoringTime(candidate.LeaseExpiresAt), candidate.FencingToken, formatAuthoringTime(candidate.UpdatedAt),
		candidate.WorkspaceID, candidate.ID, candidate.RequestFingerprint, string(current.Status), current.FencingToken,
	)
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

func (r *IdentityAuthoringRepository) Complete(ctx context.Context, completion identityauthoring.Completion) (identityauthoring.Receipt, error) {
	query := "UPDATE " + r.store.TableIdentifier("identity_authoring_receipts") + " SET " +
		r.store.Identifier("status") + " = " + r.store.Placeholder(1) + ", " +
		r.store.Identifier("result_json") + " = " + r.store.Placeholder(2) + ", " +
		r.store.Identifier("updated_at") + " = " + r.store.Placeholder(3) +
		" WHERE " + r.store.Identifier("workspace_id") + " = " + r.store.Placeholder(4) +
		" AND " + r.store.Identifier("id") + " = " + r.store.Placeholder(5) +
		" AND " + r.store.Identifier("lease_owner") + " = " + r.store.Placeholder(6) +
		" AND " + r.store.Identifier("fencing_token") + " = " + r.store.Placeholder(7) +
		" AND " + r.store.Identifier("status") + " = " + r.store.Placeholder(8)
	result, err := r.store.DB().ExecContext(ctx, query, string(completion.Status), string(completion.Result), formatAuthoringTime(completion.CompletedAt), completion.WorkspaceID, completion.ReceiptID, completion.LeaseOwner, completion.FencingToken, string(idempotency.StatusProcessing))
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

func (r *IdentityAuthoringRepository) findByKey(ctx context.Context, workspaceID, key string) (identityauthoring.Receipt, bool, error) {
	query := "SELECT " + r.store.IdentityColumns(identityAuthoringReceiptColumns()...) + " FROM " + r.store.TableIdentifier("identity_authoring_receipts") +
		" WHERE " + r.store.Identifier("workspace_id") + " = " + r.store.Placeholder(1) +
		" AND " + r.store.Identifier("idempotency_key") + " = " + r.store.Placeholder(2)
	receipt, err := scanIdentityAuthoringReceipt(r.store.DB().QueryRowContext(ctx, query, workspaceID, key))
	if errors.Is(err, sql.ErrNoRows) {
		return identityauthoring.Receipt{}, false, nil
	}
	return receipt, err == nil, err
}

func (r *IdentityAuthoringRepository) findByID(ctx context.Context, workspaceID, id string) (identityauthoring.Receipt, error) {
	query := "SELECT " + r.store.IdentityColumns(identityAuthoringReceiptColumns()...) + " FROM " + r.store.TableIdentifier("identity_authoring_receipts") +
		" WHERE " + r.store.Identifier("workspace_id") + " = " + r.store.Placeholder(1) +
		" AND " + r.store.Identifier("id") + " = " + r.store.Placeholder(2)
	return scanIdentityAuthoringReceipt(r.store.DB().QueryRowContext(ctx, query, workspaceID, id))
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
