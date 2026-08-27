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
)

func (s AuthStore) TryBeginAuthMutation(ctx context.Context, workspaceID string, request authmodel.AuthMutationClaimRequest) (authmodel.AuthMutationClaimResult, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthMutationClaimResult{}, err
	}
	if strings.TrimSpace(request.Receipt.WorkspaceID) != workspaceID {
		return authmodel.AuthMutationClaimResult{}, errors.New("auth mutation workspace does not match repository workspace")
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
	receipt.ID = authMutationReceiptID(receipt)
	receipt.RequestFingerprint, receipt.Status = strings.TrimSpace(request.RequestFingerprint), string(idempotency.StatusProcessing)
	receipt.LeaseOwner, receipt.LeaseExpiresAt, receipt.FencingToken = strings.TrimSpace(request.LeaseOwner), now.Add(request.LeaseTTL).Format(time.RFC3339Nano), 1
	receipt.CreatedAt, receipt.UpdatedAt = now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)
	columns := authMutationReceiptColumns()
	_, insertErr := s.db.ExecContext(ctx, "INSERT INTO "+s.store.TableIdentifier("auth_mutation_receipts")+" ("+s.store.IdentityColumns(columns...)+") VALUES ("+s.store.Placeholders(len(columns))+")", authMutationReceiptValues(receipt, "{}")...)
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
	query := "UPDATE " + s.store.TableIdentifier("auth_mutation_receipts") + " SET " + s.store.Identifier("status") + " = " + s.store.Placeholder(1) + ", " + s.store.Identifier("lease_owner") + " = " + s.store.Placeholder(2) + ", " + s.store.Identifier("lease_expires_at") + " = " + s.store.Placeholder(3) + ", " + s.store.Identifier("fencing_token") + " = " + s.store.Identifier("fencing_token") + " + 1, " + s.store.Identifier("updated_at") + " = " + s.store.Placeholder(4) + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(5) + " AND " + s.store.Identifier("id") + " = " + s.store.Placeholder(6) + " AND " + s.store.Identifier("request_fingerprint") + " = " + s.store.Placeholder(7) + " AND " + s.store.Identifier("status") + " = " + s.store.Placeholder(8) + " AND " + s.store.Identifier("lease_expires_at") + " <= " + s.store.Placeholder(9)
	result, err := s.db.ExecContext(ctx, query, string(idempotency.StatusProcessing), receipt.LeaseOwner, receipt.LeaseExpiresAt, receipt.UpdatedAt, workspaceID, receipt.ID, receipt.RequestFingerprint, string(idempotency.StatusProcessing), now.Format(time.RFC3339Nano))
	if err != nil {
		return authmodel.AuthMutationClaimResult{}, err
	}
	rows, err := result.RowsAffected()
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
	if rows == 1 {
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
	query := "UPDATE " + s.store.TableIdentifier("auth_mutation_receipts") + " SET " + s.store.Identifier("status") + " = " + s.store.Placeholder(1) + ", " + s.store.Identifier("result_json") + " = " + s.store.Placeholder(2) + ", " + s.store.Identifier("error_code") + " = " + s.store.Placeholder(3) + ", " + s.store.Identifier("expires_at") + " = " + s.store.Placeholder(4) + ", " + s.store.Identifier("updated_at") + " = " + s.store.Placeholder(5) + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(6) + " AND " + s.store.Identifier("id") + " = " + s.store.Placeholder(7) + " AND " + s.store.Identifier("lease_owner") + " = " + s.store.Placeholder(8) + " AND " + s.store.Identifier("fencing_token") + " = " + s.store.Placeholder(9) + " AND " + s.store.Identifier("status") + " = " + s.store.Placeholder(10)
	result, err := s.db.ExecContext(ctx, query, string(status), string(resultJSON), strings.TrimSpace(completion.ErrorCode), completion.ExpiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), workspaceID, completion.ReceiptID, strings.TrimSpace(completion.LeaseOwner), completion.FencingToken, string(idempotency.StatusProcessing))
	if err != nil {
		return authmodel.AuthMutationReceipt{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return authmodel.AuthMutationReceipt{}, err
	}
	if rows != 1 {
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
	query := "SELECT " + s.store.IdentityColumns(authMutationReceiptColumns()...) + " FROM " + s.store.TableIdentifier("auth_mutation_receipts") + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) + " AND " + s.store.Identifier("use_case") + " = " + s.store.Placeholder(2) + " AND " + s.store.Identifier("target_id") + " = " + s.store.Placeholder(3) + " AND " + s.store.Identifier("idempotency_key") + " = " + s.store.Placeholder(4)
	receipt, err := scanAuthMutationReceipt(s.db.QueryRowContext(ctx, query, scope.WorkspaceID, scope.UseCase, scope.TargetID, scope.IdempotencyKey))
	if errors.Is(err, sql.ErrNoRows) {
		return authmodel.AuthMutationReceipt{}, false, nil
	}
	return receipt, err == nil, err
}

func (s AuthStore) findAuthMutationByID(ctx context.Context, workspaceID, id string) (authmodel.AuthMutationReceipt, error) {
	query := "SELECT " + s.store.IdentityColumns(authMutationReceiptColumns()...) + " FROM " + s.store.TableIdentifier("auth_mutation_receipts") + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) + " AND " + s.store.Identifier("id") + " = " + s.store.Placeholder(2)
	return scanAuthMutationReceipt(s.db.QueryRowContext(ctx, query, workspaceID, id))
}

func authMutationReceiptColumns() []string {
	return []string{"id", "workspace_id", "use_case", "target_id", "idempotency_key", "request_fingerprint", "status", "result_json", "lease_owner", "lease_expires_at", "fencing_token", "error_code", "expires_at", "actor_id", "created_at", "updated_at"}
}

func authMutationReceiptValues(value authmodel.AuthMutationReceipt, resultJSON string) []any {
	return []any{value.ID, value.WorkspaceID, value.UseCase, value.TargetID, value.IdempotencyKey, value.RequestFingerprint, value.Status, resultJSON, value.LeaseOwner, value.LeaseExpiresAt, value.FencingToken, value.ErrorCode, value.ExpiresAt, value.ActorID, value.CreatedAt, value.UpdatedAt}
}

type authMutationScanner interface{ Scan(...any) error }

func scanAuthMutationReceipt(row authMutationScanner) (authmodel.AuthMutationReceipt, error) {
	var value authmodel.AuthMutationReceipt
	var resultJSON string
	err := row.Scan(&value.ID, &value.WorkspaceID, &value.UseCase, &value.TargetID, &value.IdempotencyKey, &value.RequestFingerprint, &value.Status, &resultJSON, &value.LeaseOwner, &value.LeaseExpiresAt, &value.FencingToken, &value.ErrorCode, &value.ExpiresAt, &value.ActorID, &value.CreatedAt, &value.UpdatedAt)
	value.Result = json.RawMessage(resultJSON)
	return value, err
}

func authMutationReceiptID(value authmodel.AuthMutationReceipt) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{strings.TrimSpace(value.WorkspaceID), strings.TrimSpace(value.UseCase), strings.TrimSpace(value.TargetID), strings.TrimSpace(value.IdempotencyKey)}, ":")))
	return "auth_mutation:" + hex.EncodeToString(sum[:])[:20]
}

func authMutationLease(value authmodel.AuthMutationReceipt) idempotency.Lease {
	expiresAt, _ := time.Parse(time.RFC3339Nano, value.LeaseExpiresAt)
	return idempotency.Lease{Owner: value.LeaseOwner, Token: value.FencingToken, ExpiresAt: expiresAt}
}
