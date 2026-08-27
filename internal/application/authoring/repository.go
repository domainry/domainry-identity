package authoring

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
)

type Repository interface {
	Claim(context.Context, Receipt, time.Duration) (Claim, error)
	Complete(context.Context, Completion) (Receipt, error)
}

// MemoryRepository is used by isolated handler tests and embedded single-
// process consumers. The SaaS server wires the SQL repository instead.
type MemoryRepository struct {
	mu       sync.Mutex
	receipts map[string]Receipt
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{receipts: map[string]Receipt{}}
}

func (r *MemoryRepository) Claim(_ context.Context, candidate Receipt, leaseTTL time.Duration) (Claim, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := candidate.WorkspaceID + "\x00" + candidate.IdempotencyKey
	current, found := r.receipts[key]
	if !found {
		r.receipts[key] = candidate
		return Claim{Decision: idempotency.DecisionAcquired, Receipt: candidate}, nil
	}
	decision := idempotency.Classify(idempotency.ReceiptState{
		Status:      current.Status,
		Fingerprint: current.RequestFingerprint,
		Lease:       idempotency.Lease{Owner: current.LeaseOwner, Token: current.FencingToken, ExpiresAt: current.LeaseExpiresAt},
	}, candidate.RequestFingerprint, candidate.UpdatedAt)
	if decision == idempotency.DecisionAcquired {
		current.Status = idempotency.StatusProcessing
		current.LeaseOwner = candidate.LeaseOwner
		current.LeaseExpiresAt = candidate.UpdatedAt.Add(leaseTTL)
		current.FencingToken++
		current.UpdatedAt = candidate.UpdatedAt
		r.receipts[key] = current
	}
	return Claim{Decision: decision, Receipt: current}, nil
}

func (r *MemoryRepository) Complete(_ context.Context, completion Completion) (Receipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, current := range r.receipts {
		if current.ID != completion.ReceiptID || current.WorkspaceID != completion.WorkspaceID {
			continue
		}
		if current.Status != idempotency.StatusProcessing || current.LeaseOwner != completion.LeaseOwner || current.FencingToken != completion.FencingToken {
			return Receipt{}, ErrLeaseLost
		}
		current.Status = completion.Status
		current.Result = append(json.RawMessage(nil), completion.Result...)
		current.UpdatedAt = completion.CompletedAt
		r.receipts[key] = current
		return current, nil
	}
	return Receipt{}, ErrReceiptUnavailable
}
