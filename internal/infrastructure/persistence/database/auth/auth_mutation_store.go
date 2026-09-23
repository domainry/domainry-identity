package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/mutation"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	operationreceipt "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/operationreceipt"
)

const (
	authMutationOperationOwner = "identity"
	authMutationOperationKind  = "identity.auth_mutation"
)

func (s AuthStore) TryBeginAuthMutation(ctx context.Context, workspaceID string, request authmodel.AuthMutationClaimRequest) (authmodel.AuthMutationClaimResult, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthMutationClaimResult{}, err
	}
	if strings.TrimSpace(request.Receipt.WorkspaceID) != workspaceID {
		return authmodel.AuthMutationClaimResult{}, errors.New("auth mutation workspace does not match repository workspace")
	}
	if !s.store.OperationsPersistenceBound() {
		return authmodel.AuthMutationClaimResult{}, errors.New("identity shared Operations persistence is not bound")
	}
	now := request.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if request.LeaseTTL <= 0 {
		request.LeaseTTL = 30 * time.Second
	}
	receipt := request.Receipt
	receipt.WorkspaceID = workspaceID
	receipt.UseCase, receipt.TargetID, receipt.IdempotencyKey = strings.TrimSpace(receipt.UseCase), strings.TrimSpace(receipt.TargetID), strings.TrimSpace(receipt.IdempotencyKey)
	receipt.ActorID = strings.TrimSpace(receipt.ActorID)
	if receipt.UseCase == "" || receipt.TargetID == "" || receipt.IdempotencyKey == "" || receipt.ActorID == "" {
		return authmodel.AuthMutationClaimResult{}, errors.New("auth mutation receipt identity is invalid")
	}
	receipt.ID = authMutationReceiptID(receipt)
	receipt.RequestFingerprint, receipt.Status = strings.TrimSpace(request.RequestFingerprint), string(idempotency.StatusProcessing)
	receipt.LeaseOwner, receipt.LeaseExpiresAt, receipt.FencingToken = strings.TrimSpace(request.LeaseOwner), now.Add(request.LeaseTTL).Format(time.RFC3339Nano), 1
	receipt.CreatedAt, receipt.UpdatedAt = now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)
	relatedIDsJSON, _ := json.Marshal([]string{receipt.TargetID})
	insertErr := operationreceipt.InsertStarted(ctx, s.db, s.store.SQLRenderer(), operationreceipt.Started{
		Leased: operationreceipt.Leased{
			ID: receipt.ID, WorkspaceID: workspaceID, ActionKey: receipt.UseCase, ResourceType: "identity_user", ResourceID: receipt.TargetID,
			IdempotencyKey: receipt.IdempotencyKey, RequestFingerprint: receipt.RequestFingerprint, RequestedBy: receipt.ActorID,
			LeaseOwner: receipt.LeaseOwner, LeaseExpiresAt: receipt.LeaseExpiresAt, FencingToken: receipt.FencingToken,
			CreatedAt: receipt.CreatedAt, UpdatedAt: receipt.UpdatedAt,
		},
		Owner: authMutationOperationOwner, Kind: authMutationOperationKind, Reason: "execute identity auth mutation", RelatedIDsJSON: relatedIDsJSON,
	})
	if insertErr == nil {
		s.observeAuthMutation(receipt.WorkspaceID, receipt.UseCase, idempotency.OutcomeAcquired)
		return authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionAcquired, Receipt: receipt}, nil
	}
	current, found, err := s.findAuthMutation(ctx, receipt)
	if err != nil {
		return authmodel.AuthMutationClaimResult{}, err
	}
	if !found {
		return authmodel.AuthMutationClaimResult{}, database.MutationConstraintError(insertErr, "auth_mutation_receipt", receipt.ID, mutation.MutationConflictIdempotency)
	}
	decision := idempotency.Classify(idempotency.ReceiptState{Status: idempotency.Status(current.Status), Fingerprint: current.RequestFingerprint, Lease: authMutationLease(current)}, receipt.RequestFingerprint, now)
	if decision != idempotency.DecisionAcquired {
		s.observeAuthMutation(receipt.WorkspaceID, receipt.UseCase, idempotency.OutcomeForDecision(decision, false))
		return authmodel.AuthMutationClaimResult{Decision: decision, Receipt: current}, nil
	}
	reclaimed, err := operationreceipt.ReclaimStarted(ctx, s.db, s.store.SQLRenderer(), operationreceipt.Reclaim{
		WorkspaceID: workspaceID, ID: receipt.ID, RequestFingerprint: receipt.RequestFingerprint,
		LeaseOwner: receipt.LeaseOwner, LeaseExpiresAt: receipt.LeaseExpiresAt, ExpectedToken: current.FencingToken,
		ExpiredAt: now.Format(time.RFC3339Nano), UpdatedAt: receipt.UpdatedAt,
	})
	if err != nil {
		return authmodel.AuthMutationClaimResult{}, err
	}
	current, found, err = s.findAuthMutation(ctx, receipt)
	if err != nil {
		return authmodel.AuthMutationClaimResult{}, err
	}
	if !found {
		return authmodel.AuthMutationClaimResult{}, sql.ErrNoRows
	}
	if reclaimed {
		s.observeAuthMutation(receipt.WorkspaceID, receipt.UseCase, idempotency.OutcomeReclaimed)
		return authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionAcquired, Receipt: current}, nil
	}
	s.observeAuthMutation(receipt.WorkspaceID, receipt.UseCase, idempotency.OutcomeInProgress)
	return authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionInProgress, Receipt: current}, nil
}

func (s AuthStore) CompleteAuthMutation(ctx context.Context, workspaceID string, completion authmodel.AuthMutationCompletion) (authmodel.AuthMutationReceipt, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthMutationReceipt{}, err
	}
	if !s.store.OperationsPersistenceBound() {
		return authmodel.AuthMutationReceipt{}, errors.New("identity shared Operations persistence is not bound")
	}
	resultJSON, err := json.Marshal(completion.Result)
	if err != nil {
		return authmodel.AuthMutationReceipt{}, err
	}
	now := completion.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	status := idempotency.StatusSucceeded
	if completion.Failed {
		status = idempotency.StatusFailedTerminal
	}
	operationStatus, err := operationreceipt.OperationStatus(status)
	if err != nil {
		return authmodel.AuthMutationReceipt{}, err
	}
	completed, err := operationreceipt.CompleteLeased(ctx, s.db, s.store.SQLRenderer(), operationreceipt.Completion{
		WorkspaceID: workspaceID, ID: completion.ReceiptID, LeaseOwner: strings.TrimSpace(completion.LeaseOwner),
		FencingToken: completion.FencingToken, Status: operationStatus, ResultJSON: resultJSON,
		ErrorCode: strings.TrimSpace(completion.ErrorCode), ExpiresAt: completion.ExpiresAt.UTC().Format(time.RFC3339Nano),
		CompletedAt: now.Format(time.RFC3339Nano),
	})
	if err != nil {
		return authmodel.AuthMutationReceipt{}, err
	}
	if !completed {
		if receipt, loadErr := s.findAuthMutationByID(ctx, workspaceID, completion.ReceiptID); loadErr == nil {
			s.observeAuthMutation(receipt.WorkspaceID, receipt.UseCase, idempotency.OutcomeLeaseLost)
		}
		return authmodel.AuthMutationReceipt{}, mutation.MutationConflict("auth_mutation", completion.ReceiptID, mutation.MutationConflictLeaseLost, nil)
	}
	return s.findAuthMutationByID(ctx, workspaceID, completion.ReceiptID)
}

func (s AuthStore) observeAuthMutation(workspaceID, scope string, outcome idempotency.Outcome) {
	if s.metrics != nil {
		s.metrics.Observe(workspaceID, scope, outcome)
	}
}

func (s AuthStore) findAuthMutation(ctx context.Context, scope authmodel.AuthMutationReceipt) (authmodel.AuthMutationReceipt, bool, error) {
	operation, found, err := operationreceipt.LoadLeasedByKey(ctx, s.db, s.store.SQLRenderer(), scope.WorkspaceID, authMutationOperationOwner, authMutationOperationKind, scope.IdempotencyKey)
	if err != nil || !found {
		return authmodel.AuthMutationReceipt{}, found, err
	}
	receipt, err := authMutationReceipt(operation)
	return receipt, err == nil, err
}

func (s AuthStore) findAuthMutationByID(ctx context.Context, workspaceID, id string) (authmodel.AuthMutationReceipt, error) {
	operation, found, err := operationreceipt.LoadLeasedByID(ctx, s.db, s.store.SQLRenderer(), workspaceID, authMutationOperationOwner, authMutationOperationKind, id)
	if err != nil || !found {
		if err == nil {
			err = sql.ErrNoRows
		}
		return authmodel.AuthMutationReceipt{}, err
	}
	return authMutationReceipt(operation)
}

func authMutationReceiptColumns() []string {
	return []string{
		"id", "workspace_id", "action_key", "resource_type", "resource_id", "idempotency_key", "request_fingerprint",
		"requested_by", "status", "result_json", "lease_owner", "lease_expires_at", "fencing_token", "error_code",
		"expires_at", "created_at", "updated_at",
	}
}

func authMutationReceipt(operation operationreceipt.Leased) (authmodel.AuthMutationReceipt, error) {
	status, err := operationreceipt.IdempotencyStatus(operation.Status)
	if err != nil {
		return authmodel.AuthMutationReceipt{}, err
	}
	return authmodel.AuthMutationReceipt{
		ID: operation.ID, WorkspaceID: operation.WorkspaceID, UseCase: operation.ActionKey, TargetID: operation.ResourceID,
		IdempotencyKey: operation.IdempotencyKey, RequestFingerprint: operation.RequestFingerprint, Status: string(status),
		Result: operation.ResultJSON, LeaseOwner: operation.LeaseOwner, LeaseExpiresAt: operation.LeaseExpiresAt,
		FencingToken: operation.FencingToken, ErrorCode: operation.ErrorCode, ExpiresAt: operation.ExpiresAt,
		ActorID: operation.RequestedBy, CreatedAt: operation.CreatedAt, UpdatedAt: operation.UpdatedAt,
	}, nil
}

func authMutationReceiptID(value authmodel.AuthMutationReceipt) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{strings.TrimSpace(value.WorkspaceID), strings.TrimSpace(value.UseCase), strings.TrimSpace(value.TargetID), strings.TrimSpace(value.IdempotencyKey)}, ":")))
	return "auth_mutation:" + hex.EncodeToString(sum[:])[:20]
}

func authMutationLease(value authmodel.AuthMutationReceipt) idempotency.Lease {
	expiresAt, _ := time.Parse(time.RFC3339Nano, value.LeaseExpiresAt)
	return idempotency.Lease{Owner: value.LeaseOwner, Token: value.FencingToken, ExpiresAt: expiresAt}
}
