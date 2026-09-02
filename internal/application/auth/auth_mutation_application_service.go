package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/requestcontext"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	authprojection "github.com/domainry/domainry-identity/internal/domain/auth/projection"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/platform/localization"
)

type authLocaleMutationReceipt struct {
	Result    authprojection.AuthMeResponse `json:"result"`
	ErrorKind apperror.ErrorKind            `json:"error_kind,omitempty"`
	ErrorCode string                        `json:"error_code,omitempty"`
}

// UpdateCurrentUserLocaleIdempotent updates exactly the authenticated user and
// stores the complete current-profile response for deterministic replay.
func (s *AuthApplicationService) UpdateCurrentUserLocaleIdempotent(ctx context.Context, principal identitymodel.Principal, accessToken, key, locale string, expectedVersion int64) (authprojection.AuthMeResponse, bool, error) {
	if !principal.Known || strings.TrimSpace(principal.UserID) == "" {
		return authprojection.AuthMeResponse{}, false, authMutationError(apperror.KindForbidden, "auth.token_required")
	}
	workspaceScope, err := identitymodel.NewWorkspaceCommandScope(principal.WorkspaceID)
	if err != nil {
		return authprojection.AuthMeResponse{}, false, authMutationErrorWithCause(apperror.KindForbidden, "backend.workspace_scope_required", err)
	}
	locale = strings.TrimSpace(locale)
	if locale == "" {
		return authprojection.AuthMeResponse{}, false, authMutationError(apperror.KindBadRequest, "backend.identity.user_locale_required")
	}
	normalized := localization.NormalizeLocale(locale)
	if !supportedAuthLocale(normalized) {
		return authprojection.AuthMeResponse{}, false, authMutationError(apperror.KindBadRequest, "backend.i18n.locale_unsupported")
	}
	if expectedVersion < 1 {
		return authprojection.AuthMeResponse{}, false, authMutationError(apperror.KindBadRequest, "backend.identity.user_version_required")
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return authprojection.AuthMeResponse{}, false, authMutationError(apperror.KindBadRequest, idempotency.ErrorCodeMissingKey)
	}
	if s.mutations == nil || s.repository == nil {
		return authprojection.AuthMeResponse{}, false, authMutationInternal(errors.New(idempotency.ErrorCodeReceiptUnavailable))
	}
	workspaceID := workspaceScope.WorkspaceID().String()
	fingerprint, err := idempotency.Fingerprint(idempotency.FingerprintInput{
		UseCase: "auth.update_current_user_locale", ResourceType: "identity_user", TargetID: principal.UserID,
		Payload: map[string]any{"locale": normalized, "expected_version": expectedVersion},
	})
	if err != nil {
		return authprojection.AuthMeResponse{}, false, authMutationInternal(err)
	}
	owner := strings.TrimSpace(principal.RequestID)
	if owner == "" {
		owner = requestcontext.RequestID(ctx)
	}
	if owner == "" {
		owner = requestcontext.NewRequestID()
	}
	claim, err := s.mutations.TryBeginAuthMutation(ctx, workspaceID, authmodel.AuthMutationClaimRequest{
		Receipt: authmodel.AuthMutationReceipt{
			WorkspaceID: workspaceID, UseCase: "auth.update_current_user_locale", TargetID: principal.UserID,
			IdempotencyKey: key, ActorID: principal.UserID,
		},
		RequestFingerprint: fingerprint, LeaseOwner: owner, LeaseTTL: 30 * time.Second, Now: time.Now().UTC(),
	})
	if err != nil {
		return authprojection.AuthMeResponse{}, false, authMutationInternal(err)
	}
	switch claim.Decision {
	case idempotency.DecisionReplay:
		s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "replayed")
		response, replayErr := replayAuthLocaleMutation(claim.Receipt.Result)
		return response, true, replayErr
	case idempotency.DecisionFingerprintConflict:
		s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "fingerprint_conflict")
		return authprojection.AuthMeResponse{}, false, authMutationError(apperror.KindConflict, idempotency.ErrorCodeKeyReused)
	case idempotency.DecisionInProgress:
		s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "in_progress")
		return authprojection.AuthMeResponse{}, false, authMutationError(apperror.KindConflict, idempotency.ErrorCodeInProgress)
	case idempotency.DecisionAcquired:
	default:
		return authprojection.AuthMeResponse{}, false, authMutationInternal(errors.New(idempotency.ErrorCodeReceiptUnavailable))
	}
	before, err := s.Me(ctx, accessToken)
	if err != nil {
		return authprojection.AuthMeResponse{}, false, err
	}
	if claim.Receipt.FencingToken > 1 && before.User.Locale == normalized && before.User.Version == expectedVersion+1 {
		if err := s.completeLocaleMutation(ctx, claim.Receipt, authLocaleMutationReceipt{Result: before}, false); err != nil {
			return authprojection.AuthMeResponse{}, false, err
		}
		s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "succeeded")
		return before, true, nil
	}
	if _, err := s.UpdateUserLocale(ctx, workspaceID, principal.UserID, normalized, expectedVersion); err != nil {
		kind := apperror.KindOf(err)
		if kind == apperror.KindInternal {
			return authprojection.AuthMeResponse{}, false, err
		}
		receipt := authLocaleMutationReceipt{ErrorKind: kind, ErrorCode: apperror.CodeOf(err)}
		if completionErr := s.completeLocaleMutation(ctx, claim.Receipt, receipt, true); completionErr != nil {
			return authprojection.AuthMeResponse{}, false, completionErr
		}
		s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "failed_terminal")
		return authprojection.AuthMeResponse{}, false, err
	}
	after, err := s.Me(ctx, accessToken)
	if err != nil {
		return authprojection.AuthMeResponse{}, false, err
	}
	if err := s.completeLocaleMutation(ctx, claim.Receipt, authLocaleMutationReceipt{Result: after}, false); err != nil {
		return authprojection.AuthMeResponse{}, false, err
	}
	if s.audit != nil {
		s.audit(ctx, "auth.current_user_locale_updated", "identity_user", principal.UserID, principal, "Updated current user locale", map[string]any{"locale": before.User.Locale, "version": before.User.Version}, map[string]any{"locale": after.User.Locale, "version": after.User.Version}, map[string]any{"workspace_id": workspaceID})
	}
	s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "succeeded")
	return after, false, nil
}

func supportedAuthLocale(locale string) bool {
	for _, supported := range localization.SupportedLocales() {
		if locale == supported {
			return true
		}
	}
	return false
}

func (s *AuthApplicationService) completeLocaleMutation(ctx context.Context, receipt authmodel.AuthMutationReceipt, result authLocaleMutationReceipt, failed bool) error {
	retention := authMutationReceiptRetention(failed)
	_, err := s.mutations.CompleteAuthMutation(ctx, receipt.WorkspaceID, authmodel.AuthMutationCompletion{
		ReceiptID: receipt.ID, LeaseOwner: receipt.LeaseOwner, FencingToken: receipt.FencingToken,
		Result: result, ErrorCode: result.ErrorCode, Failed: failed, ExpiresAt: time.Now().UTC().Add(retention), Now: time.Now().UTC(),
	})
	if err != nil {
		return authMutationInternal(err)
	}
	return nil
}

func authMutationReceiptRetention(failed bool) time.Duration {
	if failed {
		return authpolicy.AuthMutationFailureReceiptRetention
	}
	return authpolicy.AuthMutationSuccessReceiptRetention
}

func replayAuthLocaleMutation(raw json.RawMessage) (authprojection.AuthMeResponse, error) {
	var receipt authLocaleMutationReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return authprojection.AuthMeResponse{}, authMutationInternal(err)
	}
	if receipt.ErrorCode != "" {
		return authprojection.AuthMeResponse{}, &apperror.AppError{Kind: receipt.ErrorKind, Code: receipt.ErrorCode}
	}
	return receipt.Result, nil
}

type authSessionMutationReceipt struct {
	Result    authdomain.RevokeOtherSessionsResult `json:"result"`
	ErrorKind apperror.ErrorKind                   `json:"error_kind,omitempty"`
	ErrorCode string                               `json:"error_code,omitempty"`
}

func (s *AuthApplicationService) ForceLogoutUserIdempotent(ctx context.Context, principal identitymodel.Principal, key, userID string) (authdomain.RevokeOtherSessionsResult, bool, error) {
	if !principal.Known || !identitycontract.IdentityRoleHasPermissionKey(principal.Role, identitycontract.IdentityActionUsersForceLogout) {
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationError(apperror.KindForbidden, "auth.permission_denied")
	}
	userID = strings.TrimSpace(userID)
	return s.executeSessionMutation(ctx, principal, key, "auth.force_logout", userID, "", func() (authdomain.RevokeOtherSessionsResult, error) {
		count, err := s.ForceLogoutUser(ctx, principal.WorkspaceID, userID)
		return authdomain.RevokeOtherSessionsResult{RevokedSessions: count}, err
	})
}

func (s *AuthApplicationService) RevokeOtherSessionsIdempotent(ctx context.Context, principal identitymodel.Principal, accessToken, key string) (authdomain.RevokeOtherSessionsResult, bool, error) {
	if !principal.Known || strings.TrimSpace(principal.UserID) == "" {
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationError(apperror.KindForbidden, "auth.token_required")
	}
	claims, err := s.VerifyAccessToken(ctx, accessToken)
	if err != nil {
		return authdomain.RevokeOtherSessionsResult{}, false, err
	}
	if claims.Subject != principal.UserID || claims.WorkspaceID != principal.WorkspaceID {
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationError(apperror.KindForbidden, "auth.session_identity_mismatch")
	}
	return s.executeSessionMutation(ctx, principal, key, "auth.revoke_other_sessions", claims.Subject, claims.SessionID, func() (authdomain.RevokeOtherSessionsResult, error) {
		return s.RevokeOtherSessions(ctx, accessToken)
	})
}

func (s *AuthApplicationService) executeSessionMutation(ctx context.Context, principal identitymodel.Principal, key, useCase, targetID, currentSessionID string, execute func() (authdomain.RevokeOtherSessionsResult, error)) (authdomain.RevokeOtherSessionsResult, bool, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationError(apperror.KindBadRequest, idempotency.ErrorCodeMissingKey)
	}
	if _, err := identitymodel.NewWorkspaceCommandScope(principal.WorkspaceID); err != nil {
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationErrorWithCause(apperror.KindForbidden, "backend.workspace_scope_required", err)
	}
	if s.mutations == nil || len(s.pepper) == 0 {
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationInternal(errors.New(idempotency.ErrorCodeReceiptUnavailable))
	}
	fingerprint := authSessionMutationFingerprint(useCase, targetID, currentSessionID, s.pepper)
	owner := strings.TrimSpace(principal.RequestID)
	if owner == "" {
		owner = requestcontext.RequestID(ctx)
	}
	if owner == "" {
		owner = requestcontext.NewRequestID()
	}
	workspaceID := strings.TrimSpace(principal.WorkspaceID)
	claim, err := s.mutations.TryBeginAuthMutation(ctx, workspaceID, authmodel.AuthMutationClaimRequest{
		Receipt:            authmodel.AuthMutationReceipt{WorkspaceID: workspaceID, UseCase: useCase, TargetID: targetID, IdempotencyKey: key, ActorID: principal.UserID},
		RequestFingerprint: fingerprint, LeaseOwner: owner, LeaseTTL: 30 * time.Second, Now: time.Now().UTC(),
	})
	if err != nil {
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationInternal(err)
	}
	switch claim.Decision {
	case idempotency.DecisionReplay:
		return replayAuthSessionMutation(claim.Receipt.Result)
	case idempotency.DecisionFingerprintConflict:
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationError(apperror.KindConflict, idempotency.ErrorCodeKeyReused)
	case idempotency.DecisionInProgress:
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationError(apperror.KindConflict, idempotency.ErrorCodeInProgress)
	case idempotency.DecisionAcquired:
	default:
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationInternal(errors.New(idempotency.ErrorCodeReceiptUnavailable))
	}
	result, executeErr := execute()
	receipt := authSessionMutationReceipt{Result: result}
	failed := false
	if executeErr != nil {
		if apperror.KindOf(executeErr) == apperror.KindInternal {
			return authdomain.RevokeOtherSessionsResult{}, false, executeErr
		}
		receipt.ErrorKind, receipt.ErrorCode, failed = apperror.KindOf(executeErr), apperror.CodeOf(executeErr), true
	}
	retention := authpolicy.AuthMutationSuccessReceiptRetention
	if failed {
		retention = authpolicy.AuthMutationFailureReceiptRetention
	}
	if _, err := s.mutations.CompleteAuthMutation(ctx, workspaceID, authmodel.AuthMutationCompletion{ReceiptID: claim.Receipt.ID, LeaseOwner: claim.Receipt.LeaseOwner, FencingToken: claim.Receipt.FencingToken, Result: receipt, ErrorCode: receipt.ErrorCode, Failed: failed, ExpiresAt: time.Now().UTC().Add(retention), Now: time.Now().UTC()}); err != nil {
		return authdomain.RevokeOtherSessionsResult{}, false, authMutationInternal(err)
	}
	return result, false, executeErr
}

func replayAuthSessionMutation(raw json.RawMessage) (authdomain.RevokeOtherSessionsResult, bool, error) {
	var receipt authSessionMutationReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return authdomain.RevokeOtherSessionsResult{}, true, authMutationInternal(err)
	}
	if receipt.ErrorCode != "" {
		return receipt.Result, true, &apperror.AppError{Kind: receipt.ErrorKind, Code: receipt.ErrorCode}
	}
	return receipt.Result, true, nil
}

func authSessionMutationFingerprint(useCase, targetID, currentSessionID string, pepper []byte) string {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(strings.TrimSpace(useCase) + "\x00" + strings.TrimSpace(targetID) + "\x00" + strings.TrimSpace(currentSessionID)))
	return hex.EncodeToString(mac.Sum(nil))
}
