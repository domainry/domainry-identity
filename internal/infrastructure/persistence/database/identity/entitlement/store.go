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
	identitydatascope "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/datascope"
	operationreceipt "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/operationreceipt"
	roleassignmentpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/roleassignment"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type identityEntitlementReceiptQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type ScopedAssignmentWriter func(context.Context, Execer, string, identitymodel.IdentityUserRoleAssignment, identitymodel.IdentityDataScopeFilter) (bool, error)

const AssignmentInsertBatchSize = roleassignmentpersistence.InsertBatchSize

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*query.InsertBuilder, []string, ...string) *query.InsertBuilder
	OperationsPersistenceBound() bool
}

const (
	entitlementOperationOwner = "identity"
	entitlementOperationKind  = "identity.entitlement_batch"
)

type Store struct {
	backend               Backend
	now                   func() string
	writeScopedAssignment ScopedAssignmentWriter
}

func New(backend Backend, now func() string, scopedWriter ...ScopedAssignmentWriter) Store {
	store := Store{backend: backend, now: now}
	if len(scopedWriter) > 0 {
		store.writeScopedAssignment = scopedWriter[0]
	}
	return store
}

func (s Store) GetReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	workspaceID, err := workspaceIdentifier(workspaceID)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	if !s.backend.OperationsPersistenceBound() {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	return s.loadReceipt(ctx, s.backend.DB(), workspaceID, strings.TrimSpace(idempotencyKey))
}

func (s Store) GetReceiptWithinDataScope(ctx context.Context, workspaceID, idempotencyKey string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	workspaceID, err := workspaceIdentifier(workspaceID)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	if !s.backend.OperationsPersistenceBound() {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	receipt, found, err := s.loadReceipt(ctx, s.backend.DB(), workspaceID, strings.TrimSpace(idempotencyKey))
	if err != nil || !found {
		return receipt, found, err
	}
	allowed, err := s.receiptTargetsWithinDataScope(ctx, s.backend.DB(), workspaceID, receipt, scope)
	if err != nil || !allowed {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	return receipt, true, nil
}

func (s Store) Apply(ctx context.Context, mutation identitymodel.IdentityEntitlementBatchMutation) (identitymodel.IdentityEntitlementBatchReceipt, error) {
	receipt, _, err := s.apply(ctx, mutation, identitymodel.IdentityDataScopeFilter{Unrestricted: true}, false)
	return receipt, err
}

func (s Store) ApplyWithinDataScope(ctx context.Context, mutation identitymodel.IdentityEntitlementBatchMutation, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	return s.apply(ctx, mutation, scope, true)
}

func (s Store) apply(ctx context.Context, mutation identitymodel.IdentityEntitlementBatchMutation, scope identitymodel.IdentityDataScopeFilter, enforceScope bool) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	workspaceID, err := workspaceIdentifier(mutation.WorkspaceID)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	mutation.WorkspaceID = workspaceID
	mutation.ActorID = strings.TrimSpace(mutation.ActorID)
	mutation.IdempotencyKey = strings.TrimSpace(mutation.IdempotencyKey)
	mutation.RequestFingerprint = strings.TrimSpace(mutation.RequestFingerprint)
	if mutation.ActorID == "" || mutation.IdempotencyKey == "" || mutation.RequestFingerprint == "" || len(mutation.Items) == 0 || len(mutation.Items) != len(mutation.Assignments) {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, fmt.Errorf("identity entitlement batch mutation is invalid")
	}
	if !s.backend.OperationsPersistenceBound() {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	defer tx.Rollback()
	if receipt, found, loadErr := s.loadReceipt(ctx, tx, workspaceID, mutation.IdempotencyKey); loadErr != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, loadErr
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityEntitlementBatchReceipt{}, false, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.idempotency_key_reused"}
		}
		if enforceScope {
			allowed, scopeErr := s.receiptTargetsWithinDataScope(ctx, tx, workspaceID, receipt, scope)
			if scopeErr != nil || !allowed {
				return identitymodel.IdentityEntitlementBatchReceipt{}, false, scopeErr
			}
		}
		receipt.Replayed = true
		return receipt, true, nil
	}
	if enforceScope {
		if s.writeScopedAssignment == nil {
			return identitymodel.IdentityEntitlementBatchReceipt{}, false, fmt.Errorf("scoped identity role assignment writer is unavailable")
		}
		for _, assignment := range mutation.Assignments {
			allowed, writeErr := s.writeScopedAssignment(ctx, tx, workspaceID, assignment, scope)
			if writeErr != nil || !allowed {
				return identitymodel.IdentityEntitlementBatchReceipt{}, false, writeErr
			}
		}
	} else if err := roleassignmentpersistence.New(s.backend, s.now).UpsertBatch(ctx, tx, workspaceID, mutation.Assignments); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
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

	resultJSON, err := marshalEntitlementReceipt(receipt)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	relatedIDsJSON, _ := json.Marshal(entitlementRelatedIDs(receipt.Items))
	if err := operationreceipt.InsertSucceeded(ctx, tx, s.backend.SQLRenderer(), operationreceipt.Succeeded{
		ID: receipt.ID, WorkspaceID: workspaceID, Owner: entitlementOperationOwner, Kind: entitlementOperationKind,
		ActionKey: "identity.entitlements.batch", ResourceType: "identity_entitlement_batch", ResourceID: receipt.ID,
		IdempotencyKey: receipt.IdempotencyKey, RequestFingerprint: receipt.RequestFingerprint, RequestedBy: receipt.ActorID,
		Reason: "apply identity entitlement batch", ResultJSON: resultJSON, RelatedIDsJSON: relatedIDsJSON, CompletedAt: receipt.CreatedAt,
	}); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	return receipt, true, nil
}

func (s Store) receiptTargetsWithinDataScope(ctx context.Context, queryer identityEntitlementReceiptQueryer, workspaceID string, receipt identitymodel.IdentityEntitlementBatchReceipt, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	seen := make(map[string]struct{}, len(receipt.Items))
	for _, item := range receipt.Items {
		userID := strings.TrimSpace(item.UserID)
		if userID == "" {
			return false, nil
		}
		if _, checked := seen[userID]; checked {
			continue
		}
		seen[userID] = struct{}{}
		predicates := []query.Predicate{query.Equal("id", userID)}
		if !scope.Unrestricted {
			predicates = append(predicates, identitydatascope.UserPredicate(scope, query.Column("id"), query.Column("org_id")))
		}
		statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).
			Columns("id").Where(query.And(predicates...)).Build()
		if err != nil {
			return false, fmt.Errorf("build scoped entitlement receipt target: %w", err)
		}
		var persistedUserID string
		if err := queryer.QueryRowContext(ctx, statement, arguments...).Scan(&persistedUserID); errors.Is(err, sql.ErrNoRows) {
			return false, nil
		} else if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (s Store) loadReceipt(ctx context.Context, queryer identityEntitlementReceiptQueryer, workspaceID, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	operation, found, err := operationreceipt.Load(ctx, queryer, s.backend.SQLRenderer(), workspaceID, entitlementOperationOwner, entitlementOperationKind, idempotencyKey)
	if err != nil || !found {
		return identitymodel.IdentityEntitlementBatchReceipt{}, found, err
	}
	receipt, err := unmarshalEntitlementReceipt(operation.ResultJSON)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	if receipt.ID != operation.ID || receipt.WorkspaceID != workspaceID || receipt.IdempotencyKey != idempotencyKey || receipt.ActorID != operation.RequestedBy {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, fmt.Errorf("identity shared entitlement operation scope mismatch")
	}
	receipt.RequestFingerprint = operation.RequestFingerprint
	return receipt, true, nil
}

func entitlementRelatedIDs(items []identitymodel.IdentityEntitlementBatchItem) []string {
	seen := make(map[string]struct{}, len(items)*2)
	result := make([]string, 0, len(items)*2)
	for _, item := range items {
		for _, value := range []string{strings.TrimSpace(item.UserID), strings.TrimSpace(item.RoleID)} {
			if value == "" {
				continue
			}
			if _, found := seen[value]; found {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
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
