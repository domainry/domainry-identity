package auth

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	identitydomain "github.com/domainry/domainry-identity/internal/domain/identity/service"
	"golang.org/x/crypto/bcrypt"
)

type authMutationEdgeRepository struct {
	workspaceGuardAuthRepository
	claim          authmodel.AuthMutationClaimResult
	claimErr       error
	credential     identitymodel.IdentityCredential
	credentialOK   bool
	credentialErr  error
	completionErr  error
	claimRequest   authmodel.AuthMutationClaimRequest
	completion     authmodel.AuthMutationCompletion
	claimCalls     int
	completeCalls  int
	credentialGets int
	scopeChecks    int
	scopeDenied    bool
}

type authDirectorySecurityRepository struct {
	workspaceGuardAuthRepository
	facts []authmodel.UserDirectorySecurityFact
	err   error
}

func (r *authDirectorySecurityRepository) ListUserDirectorySecurityFacts(context.Context, string, []string) ([]authmodel.UserDirectorySecurityFact, error) {
	return append([]authmodel.UserDirectorySecurityFact(nil), r.facts...), r.err
}

type authSessionReissueRepository struct {
	authMutationEdgeRepository
	revokeErr   error
	revokeCalls int
}

type authSessionMutationEdgeRepository struct {
	authMutationEdgeRepository
	revoked int
}

func (r *authSessionMutationEdgeRepository) RevokeAuthRefreshTokensForUser(context.Context, string, string, string) (int, error) {
	r.calls++
	return r.revoked, nil
}

func (r *authSessionMutationEdgeRepository) RevokeAuthRefreshTokensForUserWithinDataScope(context.Context, string, string, string, identitymodel.IdentityDataScopeFilter) (int, bool, error) {
	r.calls++
	return r.revoked, true, nil
}

func (r *authSessionReissueRepository) RevokeAuthRefreshTokensForUser(context.Context, string, string, string) (int, error) {
	r.revokeCalls++
	return 0, r.revokeErr
}

type authIdentityUserRepository struct {
	identityrepository.IdentityRepository
	users []identitymodel.IdentityUser
}

func (r *authIdentityUserRepository) ListIdentityUsers(context.Context, string) ([]identitymodel.IdentityUser, error) {
	return append([]identitymodel.IdentityUser(nil), r.users...), nil
}

func (r *authMutationEdgeRepository) GetIdentityCredential(context.Context, string, string) (identitymodel.IdentityCredential, bool, error) {
	r.credentialGets++
	return r.credential, r.credentialOK, r.credentialErr
}

func (r *authMutationEdgeRepository) IdentityUserExistsWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (bool, error) {
	r.scopeChecks++
	return !r.scopeDenied, nil
}

func (r *authMutationEdgeRepository) TryBeginAuthMutation(_ context.Context, _ string, request authmodel.AuthMutationClaimRequest) (authmodel.AuthMutationClaimResult, error) {
	r.claimCalls++
	r.claimRequest = request
	return r.claim, r.claimErr
}

func (r *authMutationEdgeRepository) CompleteAuthMutation(_ context.Context, _ string, completion authmodel.AuthMutationCompletion) (authmodel.AuthMutationReceipt, error) {
	r.completeCalls++
	r.completion = completion
	return authmodel.AuthMutationReceipt{}, r.completionErr
}

func authMutationPrincipal() identitymodel.Principal {
	return identitymodel.Principal{Known: true, WorkspaceID: "workspace-1", UserID: "user-1", RequestID: "request-1", Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll,
		"auth.reset_password", "auth.providers.setup",
	)}}
}

func authAcquiredReceipt(token int64) authmodel.AuthMutationReceipt {
	return authmodel.AuthMutationReceipt{ID: "receipt-1", WorkspaceID: "workspace-1", UseCase: "auth.change_password", TargetID: "user-1", IdempotencyKey: "key-1", RequestFingerprint: "fingerprint", LeaseOwner: "request-1", FencingToken: token}
}

func TestAuthApplicationConstructionAndPasswordMutationGuards(t *testing.T) {
	repository := &authMutationEdgeRepository{}
	service := NewAuthApplicationService(nil, repository, "", "", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
	if service == nil || service.AuthDomainService == nil || service.mutations == nil || len(service.pepper) == 0 {
		t.Fatal("constructor did not wire domain service, mutation repository, and fallback pepper")
	}

	if _, err := service.ChangePasswordIdempotent(t.Context(), identitymodel.Principal{}, "key", "old", "new"); apperror.CodeOf(err) != "auth.token_required" {
		t.Fatalf("unknown principal error=%v", err)
	}
	if _, err := service.ResetPasswordIdempotent(t.Context(), identitymodel.Principal{Known: true}, "key", "user", "new", false); apperror.CodeOf(err) != "auth.permission_denied" {
		t.Fatalf("non-admin reset error=%v", err)
	}
	if _, err := service.ResetPasswordIdempotent(t.Context(), identitymodel.Principal{}, "key", "user", "new", false); apperror.CodeOf(err) != "auth.permission_denied" {
		t.Fatalf("unknown reset error=%v", err)
	}
	if _, err := service.ChangePasswordIdempotent(t.Context(), identitymodel.Principal{Known: true, WorkspaceID: "workspace-1"}, "key", "old", "new"); apperror.CodeOf(err) != "auth.token_required" {
		t.Fatalf("missing user error=%v", err)
	}
	valid := authMutationPrincipal()
	if _, err := service.ChangePasswordIdempotent(t.Context(), valid, "key", "old", "new"); apperror.KindOf(err) != apperror.KindInternal {
		t.Fatalf("valid change delegation error=%v", err)
	}
	if _, err := service.ResetPasswordIdempotent(t.Context(), valid, "key", "user", "new", false); apperror.KindOf(err) != apperror.KindInternal {
		t.Fatalf("valid reset delegation error=%v", err)
	}
	acquiredRepository := &authMutationEdgeRepository{claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionAcquired, Receipt: authAcquiredReceipt(1)}}
	delegating := NewAuthApplicationService(nil, acquiredRepository, "secret", "", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
	if _, err := delegating.ChangePasswordIdempotent(t.Context(), valid, "key", "", "new"); apperror.CodeOf(err) != "auth.password_required" {
		t.Fatalf("change domain delegation error=%v", err)
	}
	if _, err := delegating.ResetPasswordIdempotent(t.Context(), valid, "key", "user", "", false); apperror.CodeOf(err) != "auth.password_required" {
		t.Fatalf("reset domain delegation error=%v", err)
	}
	audited := NewAuthApplicationService(nil, repository, "secret", "", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{}, func(context.Context, string, string, string, identitymodel.Principal, string, map[string]any, map[string]any, map[string]any) {
	})
	if string(audited.pepper) != "secret" || audited.audit == nil {
		t.Fatal("explicit pepper or audit was not retained")
	}

	bare := &AuthApplicationService{repository: repository, mutations: repository, pepper: []byte("pepper")}
	if _, err := bare.executePasswordMutation(t.Context(), authMutationPrincipal(), " ", "auth.change_password", authpolicy.AuthPasswordMutationInput{}, func() error { return nil }); apperror.CodeOf(err) != idempotency.ErrorCodeMissingKey {
		t.Fatalf("missing key error=%v", err)
	}
	missingWorkspace := authMutationPrincipal()
	missingWorkspace.WorkspaceID = ""
	if _, err := bare.executePasswordMutation(t.Context(), missingWorkspace, "key", "auth.change_password", authpolicy.AuthPasswordMutationInput{}, func() error { return nil }); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("direct workspace error=%v", err)
	}
	for name, unavailable := range map[string]*AuthApplicationService{
		"repository": {mutations: repository, pepper: []byte("pepper")},
		"mutations":  {repository: repository, pepper: []byte("pepper")},
		"pepper":     {repository: repository, mutations: repository},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := unavailable.executePasswordMutation(t.Context(), authMutationPrincipal(), "key", "auth.change_password", authpolicy.AuthPasswordMutationInput{}, func() error { return nil }); apperror.KindOf(err) != apperror.KindInternal {
				t.Fatalf("unavailable dependency error=%v", err)
			}
		})
	}
}

func TestForceLogoutRequiresDedicatedSecurityPermissionAndReplaysStableResult(t *testing.T) {
	identity, err := identitydomain.NewIdentityDomainService(&authIdentityUserRepository{
		users: []identitymodel.IdentityUser{{ID: "target-user", Status: identitymodel.IdentityStatusActive}},
	}, nil).ForWorkspace("workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	principal := identitymodel.Principal{
		Known: true, WorkspaceID: "workspace-1", UserID: "security-admin", RequestID: "request-1",
		Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.users.update")},
	}
	repository := &authSessionMutationEdgeRepository{authMutationEdgeRepository: authMutationEdgeRepository{
		claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionAcquired, Receipt: authAcquiredReceipt(1)},
	}, revoked: 2}
	service := NewAuthApplicationService(identity, repository, "secret", "", time.Hour, 24*time.Hour, 3, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
	if _, _, gotErr := service.ForceLogoutUserIdempotent(t.Context(), principal, "force-1", "target-user"); apperror.CodeOf(gotErr) != "auth.permission_denied" || repository.claimCalls != 0 {
		t.Fatalf("identity.users.update unexpectedly authorized force logout: err=%v claims=%d", gotErr, repository.claimCalls)
	}
	principal.Role.Permissions = identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.users.force_logout")
	result, replayed, gotErr := service.ForceLogoutUserIdempotent(t.Context(), principal, "force-1", "target-user")
	if gotErr != nil || replayed || result.RevokedSessions != 2 || repository.calls != 1 || repository.completeCalls != 1 {
		t.Fatalf("result=%+v replayed=%t err=%v revokes=%d completions=%d", result, replayed, gotErr, repository.calls, repository.completeCalls)
	}

	replayRaw, err := json.Marshal(authSessionMutationReceipt{Result: result})
	if err != nil {
		t.Fatal(err)
	}
	replayRepository := &authSessionMutationEdgeRepository{authMutationEdgeRepository: authMutationEdgeRepository{
		claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionReplay, Receipt: authmodel.AuthMutationReceipt{Result: replayRaw}},
	}}
	replayService := NewAuthApplicationService(identity, replayRepository, "secret", "", time.Hour, 24*time.Hour, 3, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
	replayedResult, replayed, gotErr := replayService.ForceLogoutUserIdempotent(t.Context(), principal, "force-1", "target-user")
	if gotErr != nil || !replayed || replayedResult != result || replayRepository.calls != 0 {
		t.Fatalf("replay result=%+v replayed=%t err=%v revoke calls=%d", replayedResult, replayed, gotErr, replayRepository.calls)
	}
	if replayRepository.scopeChecks != 1 {
		t.Fatalf("replay did not reauthorize target data scope: checks=%d", replayRepository.scopeChecks)
	}
	replayRepository.scopeDenied = true
	claimCalls := replayRepository.claimCalls
	if _, _, gotErr := replayService.ForceLogoutUserIdempotent(t.Context(), principal, "force-2", "target-user"); apperror.CodeOf(gotErr) != "backend.identity.user_not_found" || replayRepository.claimCalls != claimCalls {
		t.Fatalf("scope-revoked replay reached receipt lookup: err=%v claims=%d", gotErr, replayRepository.claimCalls)
	}
	if _, _, gotErr := replayService.ForceLogoutUserIdempotent(t.Context(), principal, "", "target-user"); apperror.CodeOf(gotErr) != idempotency.ErrorCodeMissingKey {
		t.Fatalf("missing key error=%v", gotErr)
	}
}

func TestAuthUserDirectorySecurityProfiles(t *testing.T) {
	unsupported := &AuthApplicationService{repository: &workspaceGuardAuthRepository{}}
	if _, err := unsupported.UserDirectorySecurityProfiles(t.Context(), "workspace-1", []string{"user-1"}); apperror.CodeOf(err) != "backend.identity.user_directory_security_unavailable" {
		t.Fatalf("unsupported repository error=%v", err)
	}

	repositoryFailure := errors.New("directory security unavailable")
	failing := &AuthApplicationService{repository: &authDirectorySecurityRepository{err: repositoryFailure}}
	if _, err := failing.UserDirectorySecurityProfiles(t.Context(), "workspace-1", []string{"user-1"}); !errors.Is(err, repositoryFailure) {
		t.Fatalf("repository error=%v", err)
	}

	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	repository := &authDirectorySecurityRepository{facts: []authmodel.UserDirectorySecurityFact{
		{UserID: "plain", MFAEnabled: false, ActiveSessions: 0},
		{UserID: "locked", MFAEnabled: true, ActiveSessions: 2, LockedUntil: future},
		{UserID: "last-login", LastLoginAt: "2026-07-27T08:00:00Z"},
		{UserID: "expired-lock", LockedUntil: past},
		{UserID: "invalid-lock", LockedUntil: "invalid"},
	}}
	service := &AuthApplicationService{repository: repository}
	profiles, err := service.UserDirectorySecurityProfiles(t.Context(), "workspace-1", []string{"plain", "locked", "last-login", "expired-lock", "invalid-lock"})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 5 || profiles["plain"].Credential != nil || profiles["plain"].Locked {
		t.Fatalf("plain profile=%+v profiles=%d", profiles["plain"], len(profiles))
	}
	if profile := profiles["locked"]; !profile.MFAEnabled || profile.ActiveSessions != 2 || profile.Credential == nil || !profile.Locked {
		t.Fatalf("locked profile=%+v", profile)
	}
	if profile := profiles["last-login"]; profile.Credential == nil || profile.Credential.LastLoginAt == "" || profile.Locked {
		t.Fatalf("last-login profile=%+v", profile)
	}
	if profiles["expired-lock"].Locked || profiles["invalid-lock"].Locked {
		t.Fatalf("expired=%+v invalid=%+v", profiles["expired-lock"], profiles["invalid-lock"])
	}
}

func TestChangePasswordAndReissueSessionPropagatesForceLogoutFailure(t *testing.T) {
	replaySuccess, err := json.Marshal(authPasswordMutationReceipt{Result: authpolicy.AuthPasswordMutationReplay{OK: true}})
	if err != nil {
		t.Fatal(err)
	}
	revokeErr := errors.New("session revocation failed")
	repository := &authSessionReissueRepository{
		authMutationEdgeRepository: authMutationEdgeRepository{
			claim: authmodel.AuthMutationClaimResult{
				Decision: idempotency.DecisionReplay,
				Receipt:  authmodel.AuthMutationReceipt{ID: "receipt-1", Result: replaySuccess},
			},
		},
		revokeErr: revokeErr,
	}
	identity, err := identitydomain.NewIdentityDomainService(&authIdentityUserRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
	}, nil).ForWorkspace("workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	service := NewAuthApplicationService(identity, repository, "secret", "", time.Hour, 24*time.Hour, 3, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
	session, replayed, gotErr := service.ChangePasswordAndReissueSession(t.Context(), authMutationPrincipal(), "key-1", "old-password", "new-password")
	if !replayed || !errors.Is(gotErr, revokeErr) || session.AccessToken != "" || session.RefreshToken != "" {
		t.Fatalf("session=%+v replayed=%t err=%v", session, replayed, gotErr)
	}
}

func TestChangePasswordAndReissueSessionRemainingFailures(t *testing.T) {
	identity, err := identitydomain.NewIdentityDomainService(&authIdentityUserRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusDisabled}},
	}, nil).ForWorkspace("workspace-1")
	if err != nil {
		t.Fatal(err)
	}

	claimErr := errors.New("mutation claim failed")
	claimFailure := &authSessionReissueRepository{
		authMutationEdgeRepository: authMutationEdgeRepository{claimErr: claimErr},
	}
	service := NewAuthApplicationService(identity, claimFailure, "secret", "", time.Hour, 24*time.Hour, 3, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
	if session, replayed, gotErr := service.ChangePasswordAndReissueSession(t.Context(), authMutationPrincipal(), "key-1", "old-password", "new-password"); replayed || apperror.KindOf(gotErr) != apperror.KindInternal || session.AccessToken != "" || claimFailure.revokeCalls != 0 {
		t.Fatalf("claim failure session=%+v replayed=%t err=%v revokes=%d", session, replayed, gotErr, claimFailure.revokeCalls)
	}

	replaySuccess, err := json.Marshal(authPasswordMutationReceipt{Result: authpolicy.AuthPasswordMutationReplay{OK: true}})
	if err != nil {
		t.Fatal(err)
	}
	reissueFailure := &authSessionReissueRepository{
		authMutationEdgeRepository: authMutationEdgeRepository{
			claim: authmodel.AuthMutationClaimResult{
				Decision: idempotency.DecisionReplay,
				Receipt:  authmodel.AuthMutationReceipt{ID: "receipt-1", Result: replaySuccess},
			},
		},
	}
	service = NewAuthApplicationService(identity, reissueFailure, "secret", "", time.Hour, 24*time.Hour, 3, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
	if session, replayed, gotErr := service.ChangePasswordAndReissueSession(t.Context(), authMutationPrincipal(), "key-1", "old-password", "new-password"); !replayed || apperror.CodeOf(gotErr) != "auth.user_disabled" || session.AccessToken != "" || reissueFailure.revokeCalls != 1 {
		t.Fatalf("reissue failure session=%+v replayed=%t err=%v revokes=%d", session, replayed, gotErr, reissueFailure.revokeCalls)
	}
}

func TestAuthPasswordMutationClaimDecisionsAndReplay(t *testing.T) {
	replaySuccess, _ := json.Marshal(authPasswordMutationReceipt{Result: authpolicy.AuthPasswordMutationReplay{OK: true}})
	replayFailure, _ := json.Marshal(authPasswordMutationReceipt{ErrorKind: apperror.KindBadRequest, ErrorCode: "auth.password_required"})
	tests := []struct {
		name       string
		claim      authmodel.AuthMutationClaimResult
		claimErr   error
		wantReplay bool
		wantKind   apperror.ErrorKind
		wantCode   string
	}{
		{name: "replay success", claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionReplay, Receipt: authmodel.AuthMutationReceipt{ID: "receipt", Result: replaySuccess}}, wantReplay: true},
		{name: "replay failure", claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionReplay, Receipt: authmodel.AuthMutationReceipt{ID: "receipt", Result: replayFailure}}, wantReplay: true, wantKind: apperror.KindBadRequest, wantCode: "auth.password_required"},
		{name: "malformed replay", claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionReplay, Receipt: authmodel.AuthMutationReceipt{ID: "receipt", Result: json.RawMessage("{")}}, wantKind: apperror.KindInternal},
		{name: "fingerprint conflict", claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionFingerprintConflict, Receipt: authmodel.AuthMutationReceipt{ID: "receipt"}}, wantKind: apperror.KindConflict, wantCode: idempotency.ErrorCodeKeyReused},
		{name: "in progress", claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionInProgress, Receipt: authmodel.AuthMutationReceipt{ID: "receipt"}}, wantKind: apperror.KindConflict, wantCode: idempotency.ErrorCodeInProgress},
		{name: "unknown decision", claim: authmodel.AuthMutationClaimResult{}, wantKind: apperror.KindInternal},
		{name: "claim failure", claimErr: errors.New("claim failed"), wantKind: apperror.KindInternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &authMutationEdgeRepository{claim: test.claim, claimErr: test.claimErr}
			audits := 0
			service := &AuthApplicationService{repository: repository, mutations: repository, pepper: []byte("pepper"), audit: func(context.Context, string, string, string, identitymodel.Principal, string, map[string]any, map[string]any, map[string]any) {
				audits++
			}}
			replayed, err := service.executePasswordMutation(t.Context(), authMutationPrincipal(), " key-1 ", "auth.change_password", authpolicy.AuthPasswordMutationInput{UserID: "user-1", NewPassword: "new-password"}, func() error { t.Fatal("mutation executed for non-acquired claim"); return nil })
			var gotKind apperror.ErrorKind
			if err != nil {
				gotKind = apperror.KindOf(err)
			}
			if replayed != test.wantReplay || gotKind != test.wantKind || (test.wantCode != "" && apperror.CodeOf(err) != test.wantCode) {
				t.Fatalf("replayed=%v err=%v kind=%q code=%q", replayed, err, apperror.KindOf(err), apperror.CodeOf(err))
			}
			if repository.claimCalls != 1 || repository.claimRequest.Receipt.IdempotencyKey != "key-1" || repository.claimRequest.LeaseOwner != "request-1" {
				t.Fatalf("claim request=%+v calls=%d", repository.claimRequest, repository.claimCalls)
			}
			if test.claim.Receipt.ID != "" && test.claim.Decision != idempotency.DecisionAcquired && audits != 1 {
				t.Fatalf("audits=%d", audits)
			}
		})
	}
}

func TestAuthPasswordMutationAcquiredOutcomes(t *testing.T) {
	terminal := &apperror.AppError{Kind: apperror.KindBadRequest, Code: "auth.password_required"}
	tests := []struct {
		name          string
		token         int64
		credential    identitymodel.IdentityCredential
		credentialOK  bool
		credentialErr error
		executeErr    error
		completionErr error
		wantReplay    bool
		wantKind      apperror.ErrorKind
		wantComplete  int
		wantFailed    bool
		wantExec      int
	}{
		{name: "success", token: 1, wantComplete: 1, wantExec: 1},
		{name: "terminal failure", token: 1, executeErr: terminal, wantKind: apperror.KindBadRequest, wantComplete: 1, wantFailed: true, wantExec: 1},
		{name: "internal failure remains retryable", token: 1, executeErr: errors.New("storage failed"), wantKind: apperror.KindInternal, wantExec: 1},
		{name: "completion failure", token: 1, completionErr: errors.New("complete failed"), wantKind: apperror.KindInternal, wantComplete: 1, wantExec: 1},
		{name: "retry already applied", token: 2, credential: identitymodel.IdentityCredential{PasswordHash: mustAuthPasswordHash(t, "new-password")}, credentialOK: true, wantReplay: true, wantComplete: 1},
		{name: "retry already applied completion failure", token: 2, credential: identitymodel.IdentityCredential{PasswordHash: mustAuthPasswordHash(t, "new-password")}, credentialOK: true, completionErr: errors.New("complete failed"), wantKind: apperror.KindInternal, wantComplete: 1},
		{name: "retry credential absent executes", token: 2, credentialOK: false, wantComplete: 1, wantExec: 1},
		{name: "retry credential read failure", token: 2, credentialErr: errors.New("read failed"), wantKind: apperror.KindInternal},
		{name: "retry different password executes", token: 2, credential: identitymodel.IdentityCredential{PasswordHash: mustAuthPasswordHash(t, "different")}, credentialOK: true, wantComplete: 1, wantExec: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &authMutationEdgeRepository{claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionAcquired, Receipt: authAcquiredReceipt(test.token)}, credential: test.credential, credentialOK: test.credentialOK, credentialErr: test.credentialErr, completionErr: test.completionErr}
			audits, executes := 0, 0
			service := &AuthApplicationService{repository: repository, mutations: repository, pepper: []byte("pepper"), audit: func(context.Context, string, string, string, identitymodel.Principal, string, map[string]any, map[string]any, map[string]any) {
				audits++
			}}
			replayed, err := service.executePasswordMutation(t.Context(), authMutationPrincipal(), "key-1", "auth.change_password", authpolicy.AuthPasswordMutationInput{UserID: "user-1", NewPassword: "new-password"}, func() error { executes++; return test.executeErr })
			var gotKind apperror.ErrorKind
			if err != nil {
				gotKind = apperror.KindOf(err)
			}
			if replayed != test.wantReplay || gotKind != test.wantKind || repository.completeCalls != test.wantComplete || executes != test.wantExec {
				t.Fatalf("replayed=%v err=%v complete=%d executes=%d audits=%d", replayed, err, repository.completeCalls, executes, audits)
			}
			if test.wantComplete > 0 && repository.completion.Failed != test.wantFailed {
				t.Fatalf("completion=%+v", repository.completion)
			}
		})
	}
	repository := &authMutationEdgeRepository{claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionAcquired, Receipt: authAcquiredReceipt(1)}, completionErr: errors.New("terminal completion failed")}
	service := &AuthApplicationService{repository: repository, mutations: repository, pepper: []byte("pepper")}
	if _, err := service.executePasswordMutation(t.Context(), authMutationPrincipal(), "key", "auth.change_password", authpolicy.AuthPasswordMutationInput{UserID: "user", NewPassword: "new"}, func() error {
		return &apperror.AppError{Kind: apperror.KindBadRequest, Code: "auth.invalid"}
	}); apperror.KindOf(err) != apperror.KindInternal {
		t.Fatalf("terminal completion error=%v", err)
	}
}

func TestAuthPasswordMutationAuditAndOwnerFallback(t *testing.T) {
	repository := &authMutationEdgeRepository{claim: authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionAcquired, Receipt: authAcquiredReceipt(1)}}
	principal := authMutationPrincipal()
	principal.RequestID = ""
	service := &AuthApplicationService{repository: repository, mutations: repository, pepper: []byte("pepper")}
	if _, err := service.executePasswordMutation(t.Context(), principal, "key", "auth.change_password", authpolicy.AuthPasswordMutationInput{UserID: "user", NewPassword: "new-password"}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if repository.claimRequest.LeaseOwner == "" {
		t.Fatal("generated lease owner is empty")
	}
	service.auditPasswordMutationIdempotency(t.Context(), principal, authmodel.AuthMutationReceipt{}, "ignored")
}

func mustAuthPasswordHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}
