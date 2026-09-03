package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitydomain "github.com/domainry/domainry-identity/internal/domain/identity/service"
)

type identityHTTPAuthRepository struct {
	authrepository.AuthRepository
	credential identitymodel.IdentityCredential
}

func (r *identityHTTPAuthRepository) GetIdentityCredential(context.Context, string, string) (identitymodel.IdentityCredential, bool, error) {
	return r.credential, true, nil
}
func (r *identityHTTPAuthRepository) UpsertIdentityCredential(_ context.Context, _ string, credential identitymodel.IdentityCredential) error {
	r.credential = credential
	return nil
}
func (*identityHTTPAuthRepository) ListAuthRefreshTokensForUser(context.Context, string, string) ([]identitymodel.AuthRefreshToken, error) {
	return nil, nil
}
func (*identityHTTPAuthRepository) ListIdentityExternalAccounts(context.Context, string, string) ([]identitymodel.IdentityExternalAccount, error) {
	return nil, nil
}
func (*identityHTTPAuthRepository) RevokeAuthRefreshTokensForUser(context.Context, string, string, string) (int, error) {
	return 2, nil
}
func (*identityHTTPAuthRepository) IdentityUserExistsWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (bool, error) {
	return true, nil
}
func (r *identityHTTPAuthRepository) UnlockIdentityCredentialWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (bool, bool, error) {
	r.credential.FailedLoginCount = 0
	r.credential.LockedUntil = ""
	return true, true, nil
}
func (*identityHTTPAuthRepository) RevokeAuthRefreshTokensForUserWithinDataScope(context.Context, string, string, string, identitymodel.IdentityDataScopeFilter) (int, bool, error) {
	return 2, true, nil
}
func (*identityHTTPAuthRepository) RevokeIdentityMFAFactorWithinDataScope(context.Context, string, string, string, identitymodel.IdentityDataScopeFilter) (bool, bool, error) {
	return true, true, nil
}
func (*identityHTTPAuthRepository) TryBeginAuthMutation(_ context.Context, _ string, request authmodel.AuthMutationClaimRequest) (authmodel.AuthMutationClaimResult, error) {
	receipt := request.Receipt
	receipt.ID, receipt.LeaseOwner, receipt.FencingToken = "receipt", request.LeaseOwner, 1
	return authmodel.AuthMutationClaimResult{Decision: "acquired", Receipt: receipt}, nil
}
func (*identityHTTPAuthRepository) CompleteAuthMutation(_ context.Context, _ string, completion authmodel.AuthMutationCompletion) (authmodel.AuthMutationReceipt, error) {
	return authmodel.AuthMutationReceipt{ID: completion.ReceiptID}, nil
}

func TestValidateIdentityGovernanceHandlesSuccessDecodeAndServiceErrors(t *testing.T) {
	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
	handler.validateIdentityGovernance(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/identity/governance/validate", strings.NewReader(`{}`)))
	if response.status != http.StatusOK {
		t.Fatalf("success status=%d err=%v", response.status, response.err)
	}

	handler, response = newIdentityHTTPHandler(&identityHTTPRepository{})
	handler.validateIdentityGovernance(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/identity/governance/validate", strings.NewReader(`{`)))
	if response.status != http.StatusBadRequest {
		t.Fatalf("decode status=%d err=%v", response.status, response.err)
	}

	handler, response = newIdentityHTTPHandler(&identityHTTPRepository{err: errIdentityHTTPTest})
	handler.validateIdentityGovernance(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/identity/governance/validate", strings.NewReader(`{"role_id":"role-1"}`)))
	if response.status != http.StatusInternalServerError || response.err == nil {
		t.Fatalf("service status=%d err=%v", response.status, response.err)
	}
}

func TestIdentityUserActionsPropagateMissingUserErrors(t *testing.T) {
	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
	handler.userSecurity = authapplication.NewAuthApplicationService(nil, nil, "test-secret", "", time.Minute, time.Hour, 3, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
	for _, call := range []func(http.ResponseWriter, *http.Request){
		handler.identityUserSecurity,
		handler.unlockIdentityUser,
		handler.forceLogoutIdentityUser,
	} {
		response.status, response.err = 0, nil
		call(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/identity/users//action", nil))
		if response.status != http.StatusInternalServerError || response.err == nil {
			t.Fatalf("status=%d err=%v", response.status, response.err)
		}
	}
}

func TestIdentityUserActionsSuccess(t *testing.T) {
	identityRepository := &identityHTTPRepository{users: []identitymodel.IdentityUser{{ID: "user-1"}}}
	handler, response := newIdentityHTTPHandler(identityRepository)
	authRepository := &identityHTTPAuthRepository{credential: identitymodel.IdentityCredential{UserID: "user-1", FailedLoginCount: 2, LockedUntil: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}}
	handler.userSecurity = authapplication.NewAuthApplicationService(identitydomain.NewIdentityDomainService(identityRepository, nil), authRepository, "test-secret", "", time.Minute, time.Hour, 3, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
	for _, call := range []func(http.ResponseWriter, *http.Request){handler.identityUserSecurity, handler.unlockIdentityUser, handler.forceLogoutIdentityUser} {
		response.status, response.value, response.err = 0, nil, nil
		request := httptest.NewRequest(http.MethodPost, "/identity/users/user-1/action", nil)
		request.SetPathValue("userID", "user-1")
		request.Header.Set("Idempotency-Key", "force-logout-1")
		call(httptest.NewRecorder(), request)
		if response.status != http.StatusOK || response.err != nil {
			t.Fatalf("action status=%d value=%#v error=%v", response.status, response.value, response.err)
		}
	}
}
