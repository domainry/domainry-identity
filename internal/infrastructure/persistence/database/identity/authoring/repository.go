package authoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
	operationreceipt "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/operationreceipt"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	OperationsPersistenceBound() bool
}

const (
	authoringOperationOwner = "identity"
	authoringOperationKind  = "identity.authoring"
)

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
	if !r.store.OperationsPersistenceBound() {
		return identityauthoring.Claim{}, errors.New("identity shared Operations persistence is not bound")
	}
	relatedIDsJSON, _ := json.Marshal([]string{strings.TrimSpace(candidate.TargetID)})
	insertErr := operationreceipt.InsertStarted(ctx, r.store.DB(), r.store.SQLRenderer(), operationreceipt.Started{
		Leased: operationreceipt.Leased{
			ID: candidate.ID, WorkspaceID: candidate.WorkspaceID, ActionKey: candidate.UseCase,
			ResourceType: candidate.ResourceType, ResourceID: candidate.TargetID, IdempotencyKey: candidate.IdempotencyKey,
			RequestFingerprint: candidate.RequestFingerprint, RequestedBy: candidate.ActorID,
			ResultJSON: candidate.Result, LeaseOwner: candidate.LeaseOwner, LeaseExpiresAt: formatAuthoringTime(candidate.LeaseExpiresAt),
			FencingToken: candidate.FencingToken, CreatedAt: formatAuthoringTime(candidate.CreatedAt), UpdatedAt: formatAuthoringTime(candidate.UpdatedAt),
		},
		Owner: authoringOperationOwner, Kind: authoringOperationKind, Reason: "execute identity authoring mutation", RelatedIDsJSON: relatedIDsJSON,
	})
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
	reclaimed, err := operationreceipt.ReclaimStarted(ctx, r.store.DB(), r.store.SQLRenderer(), operationreceipt.Reclaim{
		WorkspaceID: candidate.WorkspaceID, ID: candidate.ID, RequestFingerprint: candidate.RequestFingerprint,
		LeaseOwner: candidate.LeaseOwner, LeaseExpiresAt: formatAuthoringTime(candidate.LeaseExpiresAt),
		ExpectedToken: current.FencingToken, ExpiredAt: formatAuthoringTime(candidate.UpdatedAt), UpdatedAt: formatAuthoringTime(candidate.UpdatedAt),
	})
	if err != nil {
		return identityauthoring.Claim{}, err
	}
	if reclaimed {
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
	if r == nil || r.store == nil || !r.store.OperationsPersistenceBound() {
		return identityauthoring.Receipt{}, errors.New("identity shared Operations persistence is not bound")
	}
	status, err := operationreceipt.OperationStatus(completion.Status)
	if err != nil {
		return identityauthoring.Receipt{}, err
	}
	errorCode := ""
	if status == operationreceipt.StatusFailed {
		var result struct {
			ErrorCode string `json:"error_code"`
		}
		_ = json.Unmarshal(completion.Result, &result)
		errorCode = result.ErrorCode
	}
	completed, err := operationreceipt.CompleteLeased(ctx, r.store.DB(), r.store.SQLRenderer(), operationreceipt.Completion{
		WorkspaceID: completion.WorkspaceID, ID: completion.ReceiptID, LeaseOwner: completion.LeaseOwner,
		FencingToken: completion.FencingToken, Status: status, ResultJSON: completion.Result,
		ErrorCode: errorCode, CompletedAt: formatAuthoringTime(completion.CompletedAt),
	})
	if err != nil {
		return identityauthoring.Receipt{}, err
	}
	if !completed {
		return identityauthoring.Receipt{}, identityauthoring.ErrLeaseLost
	}
	return r.findByID(ctx, completion.WorkspaceID, completion.ReceiptID)
}

func (r *Repository) findByKey(ctx context.Context, workspaceID, key string) (identityauthoring.Receipt, bool, error) {
	operation, found, err := operationreceipt.LoadLeasedByKey(ctx, r.store.DB(), r.store.SQLRenderer(), workspaceID, authoringOperationOwner, authoringOperationKind, key)
	if err != nil || !found {
		return identityauthoring.Receipt{}, found, err
	}
	receipt, err := identityAuthoringReceipt(operation)
	return receipt, err == nil, err
}

func (r *Repository) findByID(ctx context.Context, workspaceID, id string) (identityauthoring.Receipt, error) {
	operation, found, err := operationreceipt.LoadLeasedByID(ctx, r.store.DB(), r.store.SQLRenderer(), workspaceID, authoringOperationOwner, authoringOperationKind, id)
	if err != nil || !found {
		if err == nil {
			err = sql.ErrNoRows
		}
		return identityauthoring.Receipt{}, err
	}
	return identityAuthoringReceipt(operation)
}

func identityAuthoringReceipt(operation operationreceipt.Leased) (identityauthoring.Receipt, error) {
	status, err := operationreceipt.IdempotencyStatus(operation.Status)
	if err != nil {
		return identityauthoring.Receipt{}, err
	}
	value := identityauthoring.Receipt{
		ID: operation.ID, WorkspaceID: operation.WorkspaceID, UseCase: operation.ActionKey,
		ResourceType: operation.ResourceType, TargetID: operation.ResourceID, ActorID: operation.RequestedBy,
		IdempotencyKey: operation.IdempotencyKey, RequestFingerprint: operation.RequestFingerprint, Status: status,
		Result: operation.ResultJSON, LeaseOwner: operation.LeaseOwner, FencingToken: operation.FencingToken,
	}
	value.LeaseExpiresAt, _ = time.Parse(time.RFC3339Nano, operation.LeaseExpiresAt)
	value.CreatedAt, _ = time.Parse(time.RFC3339Nano, operation.CreatedAt)
	value.UpdatedAt, _ = time.Parse(time.RFC3339Nano, operation.UpdatedAt)
	return value, nil
}

func formatAuthoringTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
