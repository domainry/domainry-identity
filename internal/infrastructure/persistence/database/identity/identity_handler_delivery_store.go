package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	roleassignmentpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/roleassignment"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-orm/query"
)

func (s *SQLIdentityStore) GetIdentityHandlerDeliveryReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityHandlerDeliveryReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, false, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_handler_deliveries", workspaceID).
		Columns("actor_id", "idempotency_key", "request_fingerprint", "result_json", "created_at").
		Where(query.Equal("idempotency_key", strings.TrimSpace(idempotencyKey))).Limit(1).Build()
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, false, fmt.Errorf("build identity handler delivery receipt query: %w", err)
	}
	var receipt identitymodel.IdentityHandlerDeliveryReceipt
	var resultJSON string
	err = s.reader(ctx).QueryRowContext(ctx, statement, arguments...).Scan(&receipt.ActorID, &receipt.IdempotencyKey, &receipt.RequestFingerprint, &resultJSON, &receipt.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, false, err
	}
	receipt.WorkspaceID = workspaceID
	if err := json.Unmarshal([]byte(resultJSON), &receipt.Result); err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, false, fmt.Errorf("decode identity handler delivery receipt: %w", err)
	}
	return receipt, true, nil
}

func (s *SQLIdentityStore) ExecuteIdentityHandlerDelivery(ctx context.Context, mutation identitymodel.IdentityHandlerDeliveryMutation) (identitymodel.IdentityHandlerDeliveryReceipt, error) {
	executor := identitytransaction.ExecutorFromContext(ctx)
	if executor == nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, handlerDeliveryStoreError(apperror.KindInternal, "backend.identity.handler_delivery_transaction_required")
	}
	if strings.TrimSpace(mutation.ActorID) == "" || strings.TrimSpace(mutation.IdempotencyKey) == "" || strings.TrimSpace(mutation.RequestFingerprint) == "" {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, handlerDeliveryStoreError(apperror.KindBadRequest, "backend.identity.handler_delivery_invalid")
	}
	if receipt, found, err := s.GetIdentityHandlerDeliveryReceipt(ctx, mutation.WorkspaceID, mutation.IdempotencyKey); err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, err
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, handlerDeliveryStoreError(apperror.KindConflict, "backend.idempotency_key_reused")
		}
		receipt.Result.Replayed = true
		return receipt, nil
	}

	switch mutation.Operation {
	case identitymodel.IdentityHandlerUserCreate:
		if err := s.userStore().CreateWithExecutor(ctx, executor, mutation.WorkspaceID, mutation.User); err != nil {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, normalizeHandlerDeliveryWriteError(err)
		}
	case identitymodel.IdentityHandlerUserUpdate, identitymodel.IdentityHandlerUserDisable:
		updates := append([]identitymodel.IdentityUser{mutation.User}, mutation.RelatedUserUpdates...)
		updated, err := s.userStore().UpdateManyWithExecutorCAS(ctx, executor, mutation.WorkspaceID, updates, mutation.DataScope)
		if err != nil {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, err
		}
		if !updated {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, handlerDeliveryStoreError(apperror.KindConflict, "backend.identity.user_version_conflict")
		}
	default:
		return identitymodel.IdentityHandlerDeliveryReceipt{}, handlerDeliveryStoreError(apperror.KindBadRequest, "backend.identity.handler_delivery_operation_invalid")
	}
	if mutation.Credential != nil {
		if mutation.Operation != identitymodel.IdentityHandlerUserCreate || strings.TrimSpace(mutation.Credential.UserID) != strings.TrimSpace(mutation.User.ID) || strings.TrimSpace(mutation.Credential.PasswordHash) == "" {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, handlerDeliveryStoreError(apperror.KindBadRequest, "backend.identity.handler_delivery_credential_invalid")
		}
		now := nowString()
		passwordUpdatedAt := strings.TrimSpace(mutation.Credential.PasswordUpdatedAt)
		if passwordUpdatedAt == "" {
			passwordUpdatedAt = now
		}
		statement, arguments, err := query.NewWorkspaceInsertBuilder(s.sqlRenderer(), "_identity_credentials", mutation.WorkspaceID).
			Columns("user_id", "password_hash", "password_updated_at", "failed_login_count", "locked_until", "last_login_at", "must_change_password", "created_at", "updated_at").
			Values(mutation.Credential.UserID, mutation.Credential.PasswordHash, passwordUpdatedAt, 0, nil, nil, true, now, now).Build()
		if err != nil {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, fmt.Errorf("build handler delivery credential insert: %w", err)
		}
		if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, normalizeHandlerDeliveryWriteError(err)
		}
	}

	statement, arguments, err := query.NewWorkspaceDeleteBuilder(s.sqlRenderer(), "_identity_user_role_assignments", mutation.WorkspaceID).
		Where(query.And(query.Equal("user_id", mutation.User.ID), query.Equal("source", "manual"))).Build()
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, fmt.Errorf("build exact Identity role reset: %w", err)
	}
	if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, err
	}
	if err := roleassignmentpersistence.New(s, nowString).UpsertBatch(ctx, executor, mutation.WorkspaceID, mutation.RoleAssignments); err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, err
	}

	binding := mutation.ProfileBindingResult
	if mutation.ProfileBinding != nil {
		profileReceipt, err := NewIdentityProfileBindingStore(s).ExecuteIdentityProfileBindingMutation(ctx, *mutation.ProfileBinding)
		if err != nil {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, err
		}
		binding = &profileReceipt.Binding
	}

	revokedSessions := 0
	for _, userID := range uniqueHandlerDeliveryStrings(mutation.RevokeUserIDs) {
		statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "_identity_auth_refresh_tokens", mutation.WorkspaceID).
			Set("revoked_at", nowString()).Set("updated_at", nowString()).
			Where(query.And(query.Equal("user_id", userID), query.IsNull("revoked_at"))).Build()
		if err != nil {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, fmt.Errorf("build handler delivery session revocation: %w", err)
		}
		result, err := executor.ExecContext(ctx, statement, arguments...)
		if err != nil {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return identitymodel.IdentityHandlerDeliveryReceipt{}, err
		}
		revokedSessions += int(count)
	}

	user, found, err := s.GetIdentityUser(ctx, mutation.WorkspaceID, mutation.User.ID)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, err
	}
	if !found {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, handlerDeliveryStoreError(apperror.KindInternal, "backend.identity.handler_delivery_user_missing")
	}
	now := nowString()
	result := identitymodel.IdentityHandlerDeliveryResult{
		DeliveryID: handlerDeliveryStableID(mutation.WorkspaceID, mutation.IdempotencyKey), User: user,
		RoleKeys: append([]string(nil), mutation.RoleKeys...), ProfileBinding: binding, RevokedSessions: revokedSessions,
	}
	receipt := identitymodel.IdentityHandlerDeliveryReceipt{
		WorkspaceID: mutation.WorkspaceID, ActorID: mutation.ActorID, IdempotencyKey: mutation.IdempotencyKey,
		RequestFingerprint: mutation.RequestFingerprint, Result: result, CreatedAt: now,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, err
	}
	statement, arguments, err = query.NewWorkspaceInsertBuilder(s.sqlRenderer(), "_identity_handler_deliveries", mutation.WorkspaceID).
		Columns("id", "actor_id", "idempotency_key", "request_fingerprint", "result_json", "created_at").
		Values(result.DeliveryID, mutation.ActorID, mutation.IdempotencyKey, mutation.RequestFingerprint, string(resultJSON), now).Build()
	if err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, fmt.Errorf("build identity handler delivery receipt insert: %w", err)
	}
	if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
		return identitymodel.IdentityHandlerDeliveryReceipt{}, normalizeHandlerDeliveryWriteError(err)
	}
	return receipt, nil
}

func uniqueHandlerDeliveryStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func handlerDeliveryStableID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func normalizeHandlerDeliveryWriteError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique") || strings.Contains(message, "duplicate") {
		return handlerDeliveryStoreError(apperror.KindConflict, "backend.identity.handler_delivery_conflict")
	}
	return err
}

func handlerDeliveryStoreError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}

var _ identityrepository.IdentityHandlerDeliveryRepository = (*SQLIdentityStore)(nil)
