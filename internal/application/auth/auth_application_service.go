package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/logging"
	"github.com/domainry/domainry-foundation/requestcontext"
	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/platform/localization"
	"golang.org/x/crypto/bcrypt"
)

// AuthApplicationService exposes authentication use cases without owning
// Identity construction or infrastructure adapter binding.
type AuthApplicationService struct {
	*authdomain.AuthDomainService
	repository authrepository.AuthRepository
	mutations  authrepository.AuthMutationRepository
	pepper     []byte
	audit      AuthMutationAuditAppender
}

type AuthMutationAuditAppender func(context.Context, string, string, string, identitymodel.Principal, string, map[string]any, map[string]any, map[string]any)

func NewAuthApplicationService(identity authcontract.AuthIdentityPort, repository authrepository.AuthRepository, secret, defaultPassword string, accessTTL, refreshTTL time.Duration, maxLoginFailures int, loginLockDuration, otpResendCooldown time.Duration, otpMaxAttempts int, passwordPolicy authpolicy.AuthPasswordPolicy, audit ...AuthMutationAuditAppender) *AuthApplicationService {
	pepper := []byte(secret)
	if len(pepper) == 0 {
		// Production startup rejects an empty auth secret. This fallback keeps
		// isolated development/test runtimes deterministic without plaintext
		// credential fingerprints.
		pepper = []byte("domainry-runtime-development-idempotency-pepper")
	}
	domain := authdomain.NewAuthDomainService(identity, repository, secret, defaultPassword, accessTTL, refreshTTL, maxLoginFailures, loginLockDuration, otpResendCooldown, otpMaxAttempts, passwordPolicy)
	domain.ConfigureLocalePolicy(localization.DefaultLocale, localization.NormalizeLocale, localization.SupportedLocales())
	service := &AuthApplicationService{AuthDomainService: domain, repository: repository, pepper: pepper}
	if len(audit) > 0 {
		service.audit = audit[0]
	}
	service.mutations, _ = repository.(authrepository.AuthMutationRepository)
	return service
}

func (s *AuthApplicationService) UserProjectionSecurityProfiles(ctx context.Context, workspaceID string, userIDs []string) (map[string]authdomain.UserSecurityProfile, error) {
	repository, ok := s.repository.(authrepository.AuthUserProjectionSecurityRepository)
	if !ok {
		return nil, apperror.New(apperror.KindUnavailable, "backend.identity.user_projection_security_unavailable", nil, nil)
	}
	facts, err := repository.ListUserProjectionSecurityFacts(ctx, workspaceID, userIDs)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	profiles := make(map[string]authdomain.UserSecurityProfile, len(userIDs))
	for _, fact := range facts {
		profile := authdomain.UserSecurityProfile{
			MFAEnabled: fact.MFAEnabled, ActiveSessions: fact.ActiveSessions,
			Sessions: []authdomain.UserSessionSecuritySummary{}, ExternalAccounts: []authdomain.ExternalAccountSecuritySummary{}, MFAFactors: []authdomain.MFAFactorSecuritySummary{},
		}
		if fact.LockedUntil != "" || fact.LastLoginAt != "" {
			profile.Credential = &authdomain.UserCredentialSecuritySummary{UserID: fact.UserID, LockedUntil: fact.LockedUntil, LastLoginAt: fact.LastLoginAt}
		}
		if lockedUntil, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(fact.LockedUntil)); parseErr == nil {
			profile.Locked = lockedUntil.After(now)
		}
		profiles[fact.UserID] = profile
	}
	return profiles, nil
}

type authPasswordMutationReceipt struct {
	Result    authpolicy.AuthPasswordMutationReplay `json:"result"`
	ErrorKind apperror.ErrorKind                    `json:"error_kind,omitempty"`
	ErrorCode string                                `json:"error_code,omitempty"`
}

func (s *AuthApplicationService) ChangePasswordIdempotent(ctx context.Context, principal identitymodel.Principal, key, currentPassword, newPassword string) (bool, error) {
	if !principal.Known || strings.TrimSpace(principal.UserID) == "" {
		return false, authMutationError(apperror.KindForbidden, "auth.token_required")
	}
	if _, err := identitymodel.NewWorkspaceCommandScope(principal.WorkspaceID); err != nil {
		return false, authMutationErrorWithCause(apperror.KindForbidden, "backend.workspace_scope_required", err)
	}
	input := authpolicy.AuthPasswordMutationInput{UserID: principal.UserID, CurrentPassword: currentPassword, NewPassword: newPassword}
	return s.executePasswordMutation(ctx, principal, key, "auth.change_password", input, func() error {
		return s.ChangePassword(requestcontext.WithWorkspaceID(ctx, principal.WorkspaceID), principal.WorkspaceID, principal.UserID, currentPassword, newPassword)
	})
}

// ChangePasswordAndReissueSession completes the credential handoff, revokes
// every refresh session owned by the user, and returns a newly signed session.
// Idempotent replays also receive a fresh session so a lost HTTP response never
// strands the user after the password has already changed.
func (s *AuthApplicationService) ChangePasswordAndReissueSession(ctx context.Context, principal identitymodel.Principal, key, currentPassword, newPassword string) (authmodel.AuthSession, bool, error) {
	return s.ChangePasswordAndReissueSessionForAudience(ctx, principal, key, currentPassword, newPassword, "")
}

// ChangePasswordAndReissueSessionForAudience preserves the calling
// application's audience across the mandatory credential handoff.
func (s *AuthApplicationService) ChangePasswordAndReissueSessionForAudience(ctx context.Context, principal identitymodel.Principal, key, currentPassword, newPassword, audience string) (authmodel.AuthSession, bool, error) {
	ctx = requestcontext.WithWorkspaceID(ctx, principal.WorkspaceID)
	replayed, err := s.ChangePasswordIdempotent(ctx, principal, key, currentPassword, newPassword)
	if err != nil {
		return authmodel.AuthSession{}, replayed, err
	}
	if _, err := s.ForceLogoutUser(ctx, principal.WorkspaceID, principal.UserID); err != nil {
		return authmodel.AuthSession{}, replayed, err
	}
	session, err := s.IssueSessionForUserAndAudience(ctx, principal.WorkspaceID, principal.UserID, audience)
	return session, replayed, err
}

func (s *AuthApplicationService) ResetPasswordIdempotent(ctx context.Context, principal identitymodel.Principal, key, userID, newPassword string, mustChangePassword bool) (bool, error) {
	if !principal.Known || !identitycontract.IdentityRoleHasPermissionKey(principal.Role, identitycontract.IdentityActionAuthResetPassword) {
		return false, authMutationError(apperror.KindForbidden, "auth.permission_denied")
	}
	if _, err := identitymodel.NewWorkspaceCommandScope(principal.WorkspaceID); err != nil {
		return false, authMutationErrorWithCause(apperror.KindForbidden, "backend.workspace_scope_required", err)
	}
	if strings.TrimSpace(key) == "" {
		return false, authMutationError(apperror.KindBadRequest, idempotency.ErrorCodeMissingKey)
	}
	if err := s.requireIdentityUserWithinDataScope(ctx, principal, strings.TrimSpace(userID), identitycontract.IdentityActionAuthResetPassword, apperror.KindForbidden, "auth.user_disabled"); err != nil {
		return false, err
	}
	input := authpolicy.AuthPasswordMutationInput{UserID: userID, NewPassword: newPassword, MustChangePassword: mustChangePassword}
	return s.executePasswordMutation(ctx, principal, key, identitycontract.IdentityActionAuthResetPassword, input, func() error {
		return s.AuthDomainService.ResetPasswordWithinDataScope(requestcontext.WithWorkspaceID(ctx, principal.WorkspaceID), principal.WorkspaceID, userID, newPassword, mustChangePassword, identitycontract.IdentityPermissionDataScopeFilter(principal, identitycontract.IdentityActionAuthResetPassword))
	})
}

func (s *AuthApplicationService) executePasswordMutation(ctx context.Context, principal identitymodel.Principal, key, useCase string, input authpolicy.AuthPasswordMutationInput, execute func() error) (bool, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return false, authMutationError(apperror.KindBadRequest, idempotency.ErrorCodeMissingKey)
	}
	if s.mutations == nil || s.repository == nil || len(s.pepper) == 0 {
		return false, authMutationInternal(errors.New(idempotency.ErrorCodeReceiptUnavailable))
	}
	// The dependency guard above guarantees a non-empty pepper; the fixed HMAC
	// digest is therefore infallible at this application boundary.
	fingerprint, _ := authpolicy.AuthPasswordMutationFingerprint(useCase, input, s.pepper)
	owner := strings.TrimSpace(principal.RequestID)
	if owner == "" {
		owner = requestcontext.RequestID(ctx)
	}
	if owner == "" {
		owner = requestcontext.NewRequestID()
	}
	workspaceScope, err := identitymodel.NewWorkspaceCommandScope(principal.WorkspaceID)
	if err != nil {
		return false, authMutationErrorWithCause(apperror.KindForbidden, "backend.workspace_scope_required", err)
	}
	workspaceID := workspaceScope.WorkspaceID().String()
	claim, err := s.mutations.TryBeginAuthMutation(ctx, workspaceID, authmodel.AuthMutationClaimRequest{
		Receipt:            authmodel.AuthMutationReceipt{WorkspaceID: workspaceID, UseCase: useCase, TargetID: strings.TrimSpace(input.UserID), IdempotencyKey: key, ActorID: principal.UserID},
		RequestFingerprint: fingerprint, LeaseOwner: owner, LeaseTTL: 30 * time.Second, Now: time.Now().UTC(),
	})
	if err != nil {
		return false, authMutationInternal(err)
	}
	switch claim.Decision {
	case idempotency.DecisionReplay:
		s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "replayed")
		return replayAuthPasswordMutation(claim.Receipt.Result)
	case idempotency.DecisionFingerprintConflict:
		s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "fingerprint_conflict")
		return false, authMutationError(apperror.KindConflict, idempotency.ErrorCodeKeyReused)
	case idempotency.DecisionInProgress:
		s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "in_progress")
		return false, authMutationError(apperror.KindConflict, idempotency.ErrorCodeInProgress)
	case idempotency.DecisionAcquired:
	default:
		return false, authMutationInternal(errors.New(idempotency.ErrorCodeReceiptUnavailable))
	}
	if claim.Receipt.FencingToken > 1 {
		credential, found, loadErr := s.repository.GetIdentityCredential(ctx, workspaceID, strings.TrimSpace(input.UserID))
		if loadErr != nil {
			return false, authMutationInternal(loadErr)
		}
		if found && bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte(strings.TrimSpace(input.NewPassword))) == nil {
			if err := s.completePasswordMutation(ctx, claim.Receipt, authPasswordMutationReceipt{Result: authpolicy.AuthPasswordMutationReplay{OK: true}}, false); err != nil {
				return false, err
			}
			s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "succeeded")
			return true, nil
		}
	}
	if err := execute(); err != nil {
		kind := apperror.KindOf(err)
		if kind == apperror.KindInternal {
			return false, err
		}
		receipt := authPasswordMutationReceipt{ErrorKind: kind, ErrorCode: apperror.CodeOf(err)}
		if completionErr := s.completePasswordMutation(ctx, claim.Receipt, receipt, true); completionErr != nil {
			return false, completionErr
		}
		s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "failed_terminal")
		return false, err
	}
	if err := s.completePasswordMutation(ctx, claim.Receipt, authPasswordMutationReceipt{Result: authpolicy.AuthPasswordMutationReplay{OK: true}}, false); err != nil {
		return false, err
	}
	s.auditPasswordMutationIdempotency(ctx, principal, claim.Receipt, "succeeded")
	return false, nil
}

func (s *AuthApplicationService) auditPasswordMutationIdempotency(ctx context.Context, principal identitymodel.Principal, receipt authmodel.AuthMutationReceipt, status string) {
	if strings.TrimSpace(receipt.ID) == "" {
		return
	}
	facts := idempotency.AuditFacts{
		WorkspaceID: receipt.WorkspaceID, Scope: receipt.UseCase, Key: receipt.IdempotencyKey,
		RequestFingerprint: receipt.RequestFingerprint, Status: status, FencingToken: receipt.FencingToken,
	}
	metadata := idempotency.AuditMetadata(facts)
	logging.LogIdempotency(ctx, facts, principal.RequestID)
	if s.audit == nil {
		return
	}
	s.audit(ctx, "auth_mutation.idempotency_"+status, "auth", receipt.TargetID, principal, "Observed idempotent auth mutation", nil, nil, metadata)
}

func (s *AuthApplicationService) completePasswordMutation(ctx context.Context, receipt authmodel.AuthMutationReceipt, result authPasswordMutationReceipt, failed bool) error {
	retention := authpolicy.AuthMutationSuccessReceiptRetention
	if failed {
		retention = authpolicy.AuthMutationFailureReceiptRetention
	}
	_, err := s.mutations.CompleteAuthMutation(ctx, receipt.WorkspaceID, authmodel.AuthMutationCompletion{ReceiptID: receipt.ID, LeaseOwner: receipt.LeaseOwner, FencingToken: receipt.FencingToken, Result: result, ErrorCode: result.ErrorCode, Failed: failed, ExpiresAt: time.Now().UTC().Add(retention), Now: time.Now().UTC()})
	if err != nil {
		return authMutationInternal(err)
	}
	return nil
}

func replayAuthPasswordMutation(raw json.RawMessage) (bool, error) {
	var receipt authPasswordMutationReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return false, authMutationInternal(err)
	}
	if receipt.ErrorCode != "" {
		return true, &apperror.AppError{Kind: receipt.ErrorKind, Code: receipt.ErrorCode}
	}
	return true, nil
}

func authMutationError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}

func authMutationErrorWithCause(kind apperror.ErrorKind, code string, err error) error {
	return &apperror.AppError{Kind: kind, Code: code, Err: err}
}

func authMutationInternal(err error) error {
	return &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.internal", Params: map[string]string{"operation": "auth idempotent mutation"}, Err: err}
}
