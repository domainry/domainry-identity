package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	identityservice "github.com/domainry/domainry-identity/internal/domain/identity/service"
	"golang.org/x/crypto/bcrypt"
)

type authExternalIdentityRepository struct {
	identityrepository.IdentityRepository
	users        []identitymodel.IdentityUser
	roles        []identitymodel.IdentityRole
	assignments  []identitymodel.IdentityUserRoleAssignment
	roleRequests []identitymodel.IdentityRoleRequest
	rolesErr     error
	requestsErr  error
}

func (r *authExternalIdentityRepository) ListIdentityUsers(context.Context, string) ([]identitymodel.IdentityUser, error) {
	return append([]identitymodel.IdentityUser(nil), r.users...), nil
}
func (r *authExternalIdentityRepository) GetIdentityUser(_ context.Context, _ string, userID string) (identitymodel.IdentityUser, bool, error) {
	for _, user := range r.users {
		if user.ID == userID {
			return user, true, nil
		}
	}
	return identitymodel.IdentityUser{}, false, nil
}
func (r *authExternalIdentityRepository) UpdateIdentityUserLocale(_ context.Context, _ string, userID, locale string, expectedVersion int64) (identitymodel.IdentityUser, bool, error) {
	for index, user := range r.users {
		if user.ID != userID || user.Version != expectedVersion {
			continue
		}
		user.Locale, user.Version = locale, user.Version+1
		r.users[index] = user
		return user, true, nil
	}
	return identitymodel.IdentityUser{}, false, nil
}
func (r *authExternalIdentityRepository) ListIdentityRoles(context.Context, string) ([]identitymodel.IdentityRole, error) {
	return append([]identitymodel.IdentityRole(nil), r.roles...), r.rolesErr
}
func (r *authExternalIdentityRepository) ListIdentityUserRoleAssignments(_ context.Context, _ string, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	out := []identitymodel.IdentityUserRoleAssignment{}
	for _, assignment := range r.assignments {
		if userID == "" || assignment.UserID == userID {
			out = append(out, assignment)
		}
	}
	return out, nil
}
func (r *authExternalIdentityRepository) ListIdentityRoleRequests(_ context.Context, _ string, status, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	if r.requestsErr != nil {
		return nil, r.requestsErr
	}
	out := []identitymodel.IdentityRoleRequest{}
	for _, request := range r.roleRequests {
		if (status == "" || request.Status == status) && (userID == "" || request.UserID == userID) {
			out = append(out, request)
		}
	}
	return out, nil
}
func (r *authExternalIdentityRepository) CreateIdentityRoleRequest(_ context.Context, _ string, request identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error) {
	if r.requestsErr != nil {
		return identitymodel.IdentityRoleRequest{}, r.requestsErr
	}
	r.roleRequests = append(r.roleRequests, request)
	return request, nil
}

type authExternalAccountRepository struct {
	authrepository.AuthRepository
	accounts    []identitymodel.IdentityExternalAccount
	credential  identitymodel.IdentityCredential
	listErr     error
	upsertErr   error
	removeErr   error
	removedID   string
	refreshes   []identitymodel.AuthRefreshToken
	loginUserID string
	receipts    map[string]authmodel.AuthMutationReceipt
}

func (r *authExternalAccountRepository) TryBeginAuthMutation(_ context.Context, workspaceID string, request authmodel.AuthMutationClaimRequest) (authmodel.AuthMutationClaimResult, error) {
	if r.receipts == nil {
		r.receipts = map[string]authmodel.AuthMutationReceipt{}
	}
	key := workspaceID + "\x00" + request.Receipt.UseCase + "\x00" + request.Receipt.TargetID + "\x00" + request.Receipt.IdempotencyKey
	if receipt, ok := r.receipts[key]; ok {
		decision := idempotency.DecisionFingerprintConflict
		if receipt.RequestFingerprint == request.RequestFingerprint {
			decision = idempotency.DecisionReplay
		}
		return authmodel.AuthMutationClaimResult{Decision: decision, Receipt: receipt}, nil
	}
	receipt := request.Receipt
	receipt.ID, receipt.RequestFingerprint, receipt.LeaseOwner, receipt.FencingToken = "receipt-"+request.Receipt.IdempotencyKey, request.RequestFingerprint, request.LeaseOwner, 1
	r.receipts[key] = receipt
	return authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionAcquired, Receipt: receipt}, nil
}
func (r *authExternalAccountRepository) CompleteAuthMutation(_ context.Context, workspaceID string, completion authmodel.AuthMutationCompletion) (authmodel.AuthMutationReceipt, error) {
	for key, receipt := range r.receipts {
		if receipt.WorkspaceID != workspaceID || receipt.ID != completion.ReceiptID {
			continue
		}
		raw, err := json.Marshal(completion.Result)
		if err != nil {
			return authmodel.AuthMutationReceipt{}, err
		}
		receipt.Result, receipt.ErrorCode = raw, completion.ErrorCode
		r.receipts[key] = receipt
		return receipt, nil
	}
	return authmodel.AuthMutationReceipt{}, errors.New("receipt not found")
}

func (r *authExternalAccountRepository) ListIdentityExternalAccounts(_ context.Context, _ string, userID string) ([]identitymodel.IdentityExternalAccount, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	out := []identitymodel.IdentityExternalAccount{}
	for _, account := range r.accounts {
		if userID == "" || account.UserID == userID {
			out = append(out, account)
		}
	}
	return out, nil
}
func (r *authExternalAccountRepository) UpsertIdentityExternalAccount(_ context.Context, _ string, account identitymodel.IdentityExternalAccount) error {
	if r.upsertErr != nil {
		return r.upsertErr
	}
	r.accounts = append(r.accounts, account)
	return nil
}
func (r *authExternalAccountRepository) RemoveIdentityExternalAccount(_ context.Context, _ string, accountID string) error {
	r.removedID = accountID
	return r.removeErr
}
func (r *authExternalAccountRepository) GetIdentityCredential(context.Context, string, string) (identitymodel.IdentityCredential, bool, error) {
	return r.credential, r.credential.UserID != "", nil
}
func (*authExternalAccountRepository) UpsertIdentityCredential(context.Context, string, identitymodel.IdentityCredential) error {
	return nil
}
func (r *authExternalAccountRepository) RecordIdentityLoginSuccess(_ context.Context, _ string, userID, _ string) error {
	r.loginUserID = userID
	return nil
}
func (r *authExternalAccountRepository) CreateAuthRefreshToken(_ context.Context, _ string, token identitymodel.AuthRefreshToken) error {
	r.refreshes = append(r.refreshes, token)
	return nil
}

func (r *authExternalAccountRepository) AuthSessionState(_ context.Context, _, userID, sessionID string, now time.Time) (string, error) {
	foundRevoked := false
	for _, token := range r.refreshes {
		expires, _ := time.Parse(time.RFC3339, token.ExpiresAt)
		if token.UserID == userID && token.SessionID == sessionID {
			if token.RevokedAt != "" {
				foundRevoked = true
				continue
			}
			if expires.After(now) {
				return authrepository.AuthSessionStateActive, nil
			}
		}
	}
	if foundRevoked {
		return authrepository.AuthSessionStateRevoked, nil
	}
	return authrepository.AuthSessionStateMissing, nil
}

func (*authExternalAccountRepository) RevokeOtherAuthSessions(context.Context, string, string, string, string) (int, error) {
	return 0, nil
}

func (*authExternalAccountRepository) RevokeAuthSession(context.Context, string, string, string, string) (int, error) {
	return 0, nil
}

type authExternalHandlerCapture struct {
	serviceErr    error
	errorCode     string
	securityEvent string
	securityData  map[string]any
}

func newAuthExternalHandler(t *testing.T) (*AuthHandler, *authExternalIdentityRepository, *authExternalAccountRepository, *authExternalHandlerCapture, string) {
	t.Helper()
	identityRepository := &authExternalIdentityRepository{
		users:        []identitymodel.IdentityUser{{ID: "user-1", Name: "User One", Email: "user@example.com", Locale: "en-US", Version: 1, Status: identitymodel.IdentityStatusActive}},
		roles:        []identitymodel.IdentityRole{{ID: "role-viewer", Key: "viewer", Label: "Viewer", Description: "Read access", Status: identitymodel.IdentityStatusActive}},
		assignments:  []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "role-viewer"}},
		roleRequests: []identitymodel.IdentityRoleRequest{{ID: "request-existing", UserID: "user-1", RoleIDs: []string{"role-viewer"}, Status: "pending"}},
	}
	domain := identityservice.NewIdentityDomainService(identityRepository, nil)
	domain.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "viewer", Name: "Viewer", Permissions: []string{"records.read"}, RecordScope: "all_records"}})
	scoped, err := domain.ForWorkspace("workspace-a")
	if err != nil {
		t.Fatal(err)
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	authRepository := &authExternalAccountRepository{
		accounts:   []identitymodel.IdentityExternalAccount{{ID: "account-1", UserID: "user-1", Provider: "github", ProviderSubject: "github-user"}},
		credential: identitymodel.IdentityCredential{UserID: "user-1", PasswordHash: string(passwordHash)},
	}
	authService := authapplication.NewAuthApplicationService(scoped, authRepository, "test-secret", "", time.Hour, 24*time.Hour, 5, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
	session, err := authService.Login(t.Context(), "workspace-a", "user-1", "Password1!")
	if err != nil {
		t.Fatalf("issue test session: %v", err)
	}
	roleRequests := identityapplication.NewIdentityApplicationService(identityRepository, nil)
	roleRequests.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "viewer", Name: "Viewer", Permissions: []string{"records.read"}, RecordScope: "all_records"}})
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-a", UserID: "user-1", Role: identitymodel.RoleSchema{Key: "viewer"}}
	capture := &authExternalHandlerCapture{}
	handler := NewAuthHandler(AuthDependencies{
		ExternalAccounts: authService,
		RoleRequests:     roleRequests,
		Principal:        func(*http.Request) identitymodel.Principal { return principal },
		WriteJSON: func(w http.ResponseWriter, status int, value any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(value)
		},
		WriteError: func(w http.ResponseWriter, _ *http.Request, status int, code string, _ ...string) {
			capture.errorCode = code
			w.WriteHeader(status)
		},
		WriteServiceError: func(w http.ResponseWriter, _ *http.Request, err error) {
			capture.serviceErr = err
			w.WriteHeader(http.StatusUnprocessableEntity)
		},
		DecodeJSON: func(w http.ResponseWriter, r *http.Request, value any) bool {
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(value); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return false
			}
			return true
		},
		SecurityAuditForPrincipal: func(_ *http.Request, _ identitymodel.Principal, event, _ string, metadata map[string]any) {
			capture.securityEvent, capture.securityData = event, metadata
		},
	})
	return handler, identityRepository, authRepository, capture, session.AccessToken
}

func TestCurrentUserLocaleHandlerIsSelfOnlyStrictIdempotentAndConcurrent(t *testing.T) {
	handler, identityRepository, _, capture, accessToken := newAuthExternalHandler(t)
	request := func(body, key string) *http.Request {
		req := httptest.NewRequest(http.MethodPatch, "/auth/me", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		return req
	}

	missingKey := httptest.NewRecorder()
	handler.authUpdateCurrentUserLocale(missingKey, request(`{"locale":"zh-CN","expected_version":1}`, ""))
	if missingKey.Code != http.StatusBadRequest || capture.errorCode != idempotency.ErrorCodeMissingKey {
		t.Fatalf("missing key status=%d code=%q", missingKey.Code, capture.errorCode)
	}

	for _, body := range []string{
		`{"locale":"zh-CN","expected_version":1,"user_id":"user-2"}`,
		`{"locale":"zh-CN","expected_version":1,"status":"disabled"}`,
		`{"locale":"zh-CN","expected_version":1,"name":"Changed"}`,
	} {
		response := httptest.NewRecorder()
		handler.authUpdateCurrentUserLocale(response, request(body, "strict-"+body))
		if response.Code != http.StatusBadRequest || identityRepository.users[0].Version != 1 {
			t.Fatalf("privileged/target field accepted: status=%d user=%#v", response.Code, identityRepository.users[0])
		}
	}

	allowed := httptest.NewRecorder()
	handler.authUpdateCurrentUserLocale(allowed, request(`{"locale":"zh_cn","expected_version":1}`, "locale-1"))
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"locale":"zh-CN"`) || !strings.Contains(allowed.Body.String(), `"version":2`) {
		t.Fatalf("allowed update status=%d body=%s error=%v", allowed.Code, allowed.Body.String(), capture.serviceErr)
	}
	if identityRepository.users[0].Name != "User One" || identityRepository.users[0].Status != identitymodel.IdentityStatusActive {
		t.Fatalf("locale update changed another field: %#v", identityRepository.users[0])
	}

	replay := httptest.NewRecorder()
	handler.authUpdateCurrentUserLocale(replay, request(`{"locale":"zh_cn","expected_version":1}`, "locale-1"))
	if replay.Code != http.StatusOK || replay.Header().Get("Idempotency-Replayed") != "true" || identityRepository.users[0].Version != 2 {
		t.Fatalf("replay status=%d header=%q user=%#v", replay.Code, replay.Header().Get("Idempotency-Replayed"), identityRepository.users[0])
	}

	capture.serviceErr = nil
	conflict := httptest.NewRecorder()
	handler.authUpdateCurrentUserLocale(conflict, request(`{"locale":"ja-JP","expected_version":1}`, "locale-stale"))
	if apperror.CodeOf(capture.serviceErr) != "backend.identity.user_version_conflict" || identityRepository.users[0].Locale != "zh-CN" {
		t.Fatalf("stale update error=%v user=%#v", capture.serviceErr, identityRepository.users[0])
	}

	capture.serviceErr = nil
	invalid := httptest.NewRecorder()
	handler.authUpdateCurrentUserLocale(invalid, request(`{"locale":"xx-INVALID","expected_version":2}`, "locale-invalid"))
	if apperror.CodeOf(capture.serviceErr) != "backend.i18n.locale_unsupported" || identityRepository.users[0].Locale != "zh-CN" {
		t.Fatalf("invalid locale error=%v user=%#v", capture.serviceErr, identityRepository.users[0])
	}

	handler.principal = func(*http.Request) identitymodel.Principal { return identitymodel.Principal{} }
	unauthenticated := httptest.NewRecorder()
	handler.authUpdateCurrentUserLocale(unauthenticated, request(`{"locale":"ja-JP","expected_version":2}`, "locale-unauthenticated"))
	if unauthenticated.Code != http.StatusUnauthorized || capture.errorCode != "auth.token_required" || identityRepository.users[0].Locale != "zh-CN" {
		t.Fatalf("unauthenticated mutation status=%d code=%q user=%#v", unauthenticated.Code, capture.errorCode, identityRepository.users[0])
	}
}

func TestExternalAccountHandlersListBindUnbindAndMe(t *testing.T) {
	handler, _, repository, capture, accessToken := newAuthExternalHandler(t)

	listResponse := httptest.NewRecorder()
	handler.authExternalAccounts(listResponse, httptest.NewRequest(http.MethodGet, "/auth/external-accounts", nil))
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), `"account-1"`) {
		t.Fatalf("list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}

	bindRequest := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"provider_subject":"new-subject","email":" new@example.com ","display_name":" New User "}`))
	bindRequest.SetPathValue("provider", " GitHub ")
	bindResponse := httptest.NewRecorder()
	handler.authBindExternalAccount(bindResponse, bindRequest)
	if bindResponse.Code != http.StatusCreated || len(repository.accounts) != 2 || repository.accounts[1].Provider != "github" || repository.accounts[1].ProviderSubject != "new-subject" || repository.accounts[1].Email != "new@example.com" {
		t.Fatalf("bind status=%d accounts=%#v body=%s", bindResponse.Code, repository.accounts, bindResponse.Body.String())
	}

	unbindRequest := httptest.NewRequest(http.MethodDelete, "/", nil)
	unbindRequest.SetPathValue("provider", "github")
	unbindRequest.SetPathValue("accountID", "account-1")
	unbindResponse := httptest.NewRecorder()
	handler.authUnbindExternalAccount(unbindResponse, unbindRequest)
	if unbindResponse.Code != http.StatusOK || repository.removedID != "account-1" || !strings.Contains(unbindResponse.Body.String(), `"ok":true`) {
		t.Fatalf("unbind status=%d removed=%q body=%s", unbindResponse.Code, repository.removedID, unbindResponse.Body.String())
	}

	meRequest := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meRequest.Header.Set("Authorization", "bearer "+accessToken)
	meResponse := httptest.NewRecorder()
	handler.authMe(meResponse, meRequest)
	if meResponse.Code != http.StatusOK || !strings.Contains(meResponse.Body.String(), `"id":"user-1"`) || !strings.Contains(meResponse.Body.String(), `"records.read"`) {
		t.Fatalf("me status=%d body=%s", meResponse.Code, meResponse.Body.String())
	}

	capture.serviceErr = nil
	invalidMeResponse := httptest.NewRecorder()
	handler.authMe(invalidMeResponse, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
	if invalidMeResponse.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil {
		t.Fatalf("invalid me status=%d error=%v", invalidMeResponse.Code, capture.serviceErr)
	}
}

func TestExternalAccountHandlersAuthenticationDecodeAndServiceErrors(t *testing.T) {
	handler, _, repository, capture, _ := newAuthExternalHandler(t)
	handler.principal = func(*http.Request) identitymodel.Principal { return identitymodel.Principal{} }
	for _, test := range []struct {
		name   string
		handle func(http.ResponseWriter, *http.Request)
	}{
		{name: "list", handle: handler.authExternalAccounts},
		{name: "bind", handle: handler.authBindExternalAccount},
		{name: "unbind", handle: handler.authUnbindExternalAccount},
	} {
		t.Run(test.name, func(t *testing.T) {
			capture.errorCode = ""
			response := httptest.NewRecorder()
			test.handle(response, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
			if response.Code != http.StatusForbidden || capture.errorCode != "auth.token_required" {
				t.Fatalf("status=%d code=%q", response.Code, capture.errorCode)
			}
		})
	}

	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{Known: true, WorkspaceID: "workspace-a", UserID: "user-1"}
	}
	badJSONResponse := httptest.NewRecorder()
	handler.authBindExternalAccount(badJSONResponse, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{")))
	if badJSONResponse.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON status = %d", badJSONResponse.Code)
	}

	repository.listErr = errors.New("list failed")
	for _, handle := range []func(http.ResponseWriter, *http.Request){handler.authExternalAccounts, handler.authUnbindExternalAccount} {
		capture.serviceErr = nil
		response := httptest.NewRecorder()
		handle(response, httptest.NewRequest(http.MethodGet, "/", nil))
		if response.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil {
			t.Fatalf("service failure status=%d error=%v", response.Code, capture.serviceErr)
		}
	}

	repository.listErr = nil
	repository.upsertErr = errors.New("bind failed")
	capture.serviceErr = nil
	bindRequest := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"subject":"subject"}`))
	bindRequest.SetPathValue("provider", "github")
	bindResponse := httptest.NewRecorder()
	handler.authBindExternalAccount(bindResponse, bindRequest)
	if bindResponse.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil {
		t.Fatalf("bind failure status=%d error=%v", bindResponse.Code, capture.serviceErr)
	}
}

func TestAuthRoleHandlersOptionsRequestsCreationAndErrors(t *testing.T) {
	handler, identityRepository, repository, capture, _ := newAuthExternalHandler(t)

	optionsResponse := httptest.NewRecorder()
	handler.authRoleOptions(optionsResponse, httptest.NewRequest(http.MethodGet, "/auth/role-options", nil))
	if optionsResponse.Code != http.StatusOK || !strings.Contains(optionsResponse.Body.String(), `"id":"role-viewer"`) {
		t.Fatalf("options status=%d error=%v body=%s", optionsResponse.Code, capture.serviceErr, optionsResponse.Body.String())
	}

	requestsResponse := httptest.NewRecorder()
	handler.authRoleRequests(requestsResponse, httptest.NewRequest(http.MethodGet, "/auth/role-requests?status=%20pending%20", nil))
	if requestsResponse.Code != http.StatusOK || !strings.Contains(requestsResponse.Body.String(), `"request-existing"`) {
		t.Fatalf("requests status=%d body=%s", requestsResponse.Code, requestsResponse.Body.String())
	}

	createResponse := httptest.NewRecorder()
	handler.authCreateRoleRequest(createResponse, httptest.NewRequest(http.MethodPost, "/auth/role-requests", strings.NewReader(`{"role_ids":["viewer"],"reason":" Need access "}`)))
	if createResponse.Code != http.StatusCreated || capture.securityEvent != "auth_role_request_submitted" || capture.securityData["provider"] != "github" || len(identityRepository.roleRequests) != 2 || identityRepository.roleRequests[1].ProviderSubject != "github-user" {
		t.Fatalf("create status=%d event=%q data=%#v requests=%#v body=%s", createResponse.Code, capture.securityEvent, capture.securityData, identityRepository.roleRequests, createResponse.Body.String())
	}

	provider, subject := handler.primaryExternalAccountForUser(t.Context(), "workspace-a", "user-1")
	if provider != "github" || subject != "github-user" {
		t.Fatalf("primary account = %q/%q", provider, subject)
	}
	repository.listErr = errors.New("primary failed")
	if provider, subject := handler.primaryExternalAccountForUser(t.Context(), "workspace-a", "user-1"); provider != "" || subject != "" {
		t.Fatalf("failed primary account = %q/%q", provider, subject)
	}
	repository.listErr = nil
	repository.accounts = nil
	if provider, subject := handler.primaryExternalAccountForUser(t.Context(), "workspace-a", "user-1"); provider != "" || subject != "" {
		t.Fatalf("empty primary account = %q/%q", provider, subject)
	}

	projected := authRoleOptions([]identitymodel.IdentityRole{{ID: "role", Key: "key", Label: "Label", Description: "Description", Status: identitymodel.IdentityStatusDisabled}})
	if len(projected) != 1 || projected[0]["description"] != "Description" || projected[0]["status"] != identitymodel.IdentityStatusDisabled {
		t.Fatalf("projected role options = %#v", projected)
	}

	handler.principal = func(*http.Request) identitymodel.Principal { return identitymodel.Principal{} }
	for _, handle := range []func(http.ResponseWriter, *http.Request){handler.authRoleOptions, handler.authRoleRequests, handler.authCreateRoleRequest} {
		capture.errorCode = ""
		response := httptest.NewRecorder()
		handle(response, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
		if response.Code != http.StatusUnauthorized || capture.errorCode != "auth.token_required" {
			t.Fatalf("unauthorized role handler status=%d code=%q", response.Code, capture.errorCode)
		}
	}
}

func TestAuthRoleHandlersDecodeAndRepositoryFailures(t *testing.T) {
	handler, identityRepository, _, capture, _ := newAuthExternalHandler(t)

	badJSONResponse := httptest.NewRecorder()
	handler.authCreateRoleRequest(badJSONResponse, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{")))
	if badJSONResponse.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON status = %d", badJSONResponse.Code)
	}

	identityRepository.rolesErr = errors.New("roles failed")
	capture.serviceErr = nil
	optionsResponse := httptest.NewRecorder()
	handler.authRoleOptions(optionsResponse, httptest.NewRequest(http.MethodGet, "/", nil))
	if optionsResponse.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil {
		t.Fatalf("role options failure status=%d error=%v", optionsResponse.Code, capture.serviceErr)
	}

	identityRepository.rolesErr = nil
	identityRepository.requestsErr = errors.New("requests failed")
	for _, handle := range []func(http.ResponseWriter, *http.Request){handler.authRoleRequests, handler.authCreateRoleRequest} {
		capture.serviceErr = nil
		response := httptest.NewRecorder()
		handle(response, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"role_ids":["viewer"]}`)))
		if response.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil {
			t.Fatalf("role request failure status=%d error=%v", response.Code, capture.serviceErr)
		}
	}
}
