package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityservice "github.com/domainry/domainry-identity/internal/domain/identity/service"
	"golang.org/x/crypto/bcrypt"
)

type authPasswordRepository struct {
	*authExternalAccountRepository
	receipts      map[string]authmodel.AuthMutationReceipt
	credentialErr error
	refreshErr    error
	mutationErr   error
	completionErr error
}

func (r *authPasswordRepository) GetIdentityCredential(_ context.Context, _ string, userID string) (identitymodel.IdentityCredential, bool, error) {
	if r.credentialErr != nil {
		return identitymodel.IdentityCredential{}, false, r.credentialErr
	}
	credential := r.authExternalAccountRepository.credential
	return credential, credential.UserID == userID, nil
}

func (r *authPasswordRepository) UpsertIdentityCredential(_ context.Context, _ string, credential identitymodel.IdentityCredential) error {
	if r.credentialErr != nil {
		return r.credentialErr
	}
	r.authExternalAccountRepository.credential = credential
	return nil
}

func (r *authPasswordRepository) GetAuthRefreshTokenByHash(_ context.Context, _ string, hash string) (identitymodel.AuthRefreshToken, bool, error) {
	if r.refreshErr != nil {
		return identitymodel.AuthRefreshToken{}, false, r.refreshErr
	}
	for _, token := range r.refreshes {
		if token.TokenHash == hash {
			return token, true, nil
		}
	}
	return identitymodel.AuthRefreshToken{}, false, nil
}

func (r *authPasswordRepository) RevokeAuthRefreshToken(_ context.Context, _ string, tokenID, revokedAt, replacedByID string) error {
	if r.refreshErr != nil {
		return r.refreshErr
	}
	for index := range r.refreshes {
		if r.refreshes[index].ID == tokenID {
			r.refreshes[index].RevokedAt = revokedAt
			r.refreshes[index].ReplacedByID = replacedByID
		}
	}
	return nil
}

func (r *authPasswordRepository) RotateAuthRefreshToken(_ context.Context, _ string, tokenID, revokedAt string, replacement identitymodel.AuthRefreshToken) (bool, error) {
	if r.refreshErr != nil {
		return false, r.refreshErr
	}
	for index := range r.refreshes {
		if r.refreshes[index].ID != tokenID || r.refreshes[index].RevokedAt != "" {
			continue
		}
		r.refreshes[index].RevokedAt = revokedAt
		r.refreshes[index].ReplacedByID = replacement.ID
		r.refreshes = append(r.refreshes, replacement)
		return true, nil
	}
	return false, nil
}

func (r *authPasswordRepository) ListAuthRefreshTokensForUser(_ context.Context, _ string, userID string) ([]identitymodel.AuthRefreshToken, error) {
	if r.refreshErr != nil {
		return nil, r.refreshErr
	}
	out := []identitymodel.AuthRefreshToken{}
	for _, token := range r.refreshes {
		if token.UserID == userID {
			out = append(out, token)
		}
	}
	return out, nil
}

func (r *authPasswordRepository) RevokeAuthRefreshTokensForUser(_ context.Context, _ string, userID, revokedAt string) (int, error) {
	if r.refreshErr != nil {
		return 0, r.refreshErr
	}
	count := 0
	for index := range r.refreshes {
		if r.refreshes[index].UserID == userID && r.refreshes[index].RevokedAt == "" {
			r.refreshes[index].RevokedAt = revokedAt
			count++
		}
	}
	return count, nil
}

func (r *authPasswordRepository) RevokeAuthSession(_ context.Context, _ string, userID, sessionID, revokedAt string) (int, error) {
	if r.refreshErr != nil {
		return 0, r.refreshErr
	}
	changed := false
	for index := range r.refreshes {
		if r.refreshes[index].UserID == userID && r.refreshes[index].SessionID == sessionID && r.refreshes[index].RevokedAt == "" {
			r.refreshes[index].RevokedAt = revokedAt
			changed = true
		}
	}
	if changed {
		return 1, nil
	}
	return 0, nil
}

func (r *authPasswordRepository) RevokeOtherAuthSessions(_ context.Context, _ string, userID, currentSessionID, revokedAt string) (int, error) {
	if r.refreshErr != nil {
		return 0, r.refreshErr
	}
	changed := map[string]struct{}{}
	for index := range r.refreshes {
		if r.refreshes[index].UserID == userID && r.refreshes[index].SessionID != currentSessionID && r.refreshes[index].RevokedAt == "" {
			r.refreshes[index].RevokedAt = revokedAt
			changed[r.refreshes[index].SessionID] = struct{}{}
		}
	}
	return len(changed), nil
}

func authMutationReceiptKey(workspaceID string, request authmodel.AuthMutationClaimRequest) string {
	return workspaceID + "|" + request.Receipt.UseCase + "|" + request.Receipt.IdempotencyKey
}

func (r *authPasswordRepository) TryBeginAuthMutation(_ context.Context, workspaceID string, request authmodel.AuthMutationClaimRequest) (authmodel.AuthMutationClaimResult, error) {
	if r.mutationErr != nil {
		return authmodel.AuthMutationClaimResult{}, r.mutationErr
	}
	key := authMutationReceiptKey(workspaceID, request)
	if receipt, found := r.receipts[key]; found {
		decision := idempotency.DecisionReplay
		if receipt.RequestFingerprint != request.RequestFingerprint {
			decision = idempotency.DecisionFingerprintConflict
		}
		return authmodel.AuthMutationClaimResult{Decision: decision, Receipt: receipt}, nil
	}
	receipt := request.Receipt
	receipt.ID = "receipt-" + strings.ReplaceAll(key, "|", "-")
	receipt.RequestFingerprint = request.RequestFingerprint
	receipt.LeaseOwner = request.LeaseOwner
	receipt.FencingToken = 1
	receipt.Status = string(idempotency.StatusProcessing)
	r.receipts[key] = receipt
	return authmodel.AuthMutationClaimResult{Decision: idempotency.DecisionAcquired, Receipt: receipt}, nil
}

func (r *authPasswordRepository) CompleteAuthMutation(_ context.Context, _ string, completion authmodel.AuthMutationCompletion) (authmodel.AuthMutationReceipt, error) {
	if r.completionErr != nil {
		return authmodel.AuthMutationReceipt{}, r.completionErr
	}
	for key, receipt := range r.receipts {
		if receipt.ID != completion.ReceiptID {
			continue
		}
		result, err := json.Marshal(completion.Result)
		if err != nil {
			return authmodel.AuthMutationReceipt{}, err
		}
		receipt.Result = result
		receipt.ErrorCode = completion.ErrorCode
		if completion.Failed {
			receipt.Status = string(idempotency.StatusFailedTerminal)
		} else {
			receipt.Status = string(idempotency.StatusSucceeded)
		}
		r.receipts[key] = receipt
		return receipt, nil
	}
	return authmodel.AuthMutationReceipt{}, errors.New("receipt not found")
}

func (r *authExternalIdentityRepository) UpsertIdentityUser(_ context.Context, _ string, user identitymodel.IdentityUser) error {
	for index := range r.users {
		if r.users[index].ID == user.ID {
			r.users[index] = user
			return nil
		}
	}
	r.users = append(r.users, user)
	return nil
}

func (r *authExternalIdentityRepository) UpsertIdentityUsersAtomically(ctx context.Context, workspaceID string, users []identitymodel.IdentityUser) error {
	for _, user := range users {
		if err := r.UpsertIdentityUser(ctx, workspaceID, user); err != nil {
			return err
		}
	}
	return nil
}

func (*authExternalIdentityRepository) ListIdentityDepartments(context.Context, string) ([]identitymodel.IdentityDepartment, error) {
	return []identitymodel.IdentityDepartment{{ID: "company", Name: "Company", Status: identitymodel.IdentityStatusActive}}, nil
}

func (r *authExternalIdentityRepository) AssignIdentityUserRole(_ context.Context, _ string, assignment identitymodel.IdentityUserRoleAssignment) error {
	r.assignments = append(r.assignments, assignment)
	return nil
}

func newAuthPasswordHandler(t *testing.T) (*AuthHandler, *authExternalIdentityRepository, *authPasswordRepository, *authExternalHandlerCapture, *identitymodel.Principal) {
	t.Helper()
	identityRepository := &authExternalIdentityRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Name: "User One", Email: "user@example.com", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{
			{ID: "role-viewer", Key: "viewer", Label: "Viewer", Status: identitymodel.IdentityStatusActive},
			{ID: "role-customer", Key: "customer", Label: "Customer", Status: identitymodel.IdentityStatusActive},
		},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "role-viewer"}},
	}
	domain := identityservice.NewIdentityDomainService(identityRepository, nil)
	roleDefinitions := []identitymodel.RoleSchema{
		{Key: "viewer", Name: "Viewer", Permissions: []string{"identity.users.read"}},
		{Key: "customer", Name: "Customer"},
	}
	domain.ReplaceRoleDefinitions(roleDefinitions)
	scoped, err := domain.ForWorkspace("workspace-a")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	repository := &authPasswordRepository{
		authExternalAccountRepository: &authExternalAccountRepository{credential: identitymodel.IdentityCredential{UserID: "user-1", PasswordHash: string(hash)}},
		receipts:                      map[string]authmodel.AuthMutationReceipt{},
	}
	service := authapplication.NewAuthApplicationService(scoped, repository, "test-secret", "", time.Hour, 24*time.Hour, 5, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
	principal := &identitymodel.Principal{Known: true, WorkspaceID: "workspace-a", UserID: "user-1", Role: identitymodel.RoleSchema{Key: "viewer"}}
	roleRequests := identityapplication.NewIdentityApplicationService(identityRepository, nil)
	roleRequests.ReplaceRoleDefinitions(roleDefinitions)
	capture := &authExternalHandlerCapture{}
	handler := NewAuthHandler(AuthDependencies{
		Passwords:    service,
		RoleRequests: roleRequests,
		Principal:    func(*http.Request) identitymodel.Principal { return *principal },
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
			if err := json.NewDecoder(r.Body).Decode(value); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return false
			}
			return true
		},
		SecurityAudit: func(_ *http.Request, event, _ string, metadata map[string]any) {
			capture.securityEvent, capture.securityData = event, metadata
		},
		SecurityAuditForPrincipal: func(_ *http.Request, _ identitymodel.Principal, event, _ string, metadata map[string]any) {
			capture.securityEvent, capture.securityData = event, metadata
		},
	})
	return handler, identityRepository, repository, capture, principal
}

func TestPasswordSessionHandlersLoginGuestRefreshAndLogout(t *testing.T) {
	handler, identities, repository, _, _ := newAuthPasswordHandler(t)
	repository.credential.MustChangePassword = true
	surfaceRequest := func(path, body, surface string) *http.Request {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("X-Domainry-Product-Surface", surface)
		return request
	}

	loginResponse := httptest.NewRecorder()
	handler.authLogin(loginResponse, surfaceRequest("/auth/login", `{"workspace_id":" workspace-a ","email":" user@example.com ","password":"Password1!"}`, "admin_console"))
	var loginSession authmodel.AuthSession
	if loginResponse.Code != http.StatusOK || json.Unmarshal(loginResponse.Body.Bytes(), &loginSession) != nil || loginSession.User.ID != "user-1" || loginSession.RefreshToken == "" || !loginSession.MustChangePassword ||
		!slices.Contains(loginSession.Permissions, "identity.users.read") ||
		repository.loginUserID != "user-1" {
		t.Fatalf("login status=%d session=%#v loginUser=%q body=%s", loginResponse.Code, loginSession, repository.loginUserID, loginResponse.Body.String())
	}
	if cookies := loginResponse.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Fatalf("login must return bearer credentials in JSON, not a cross-host cookie: %v", cookies)
	}

	refreshResponse := httptest.NewRecorder()
	handler.authRefresh(refreshResponse, surfaceRequest("/auth/refresh", `{"workspace_id":"workspace-a","refresh_token":"`+loginSession.RefreshToken+`"}`, "admin_console"))
	var refreshed authmodel.AuthSession
	if refreshResponse.Code != http.StatusOK || json.Unmarshal(refreshResponse.Body.Bytes(), &refreshed) != nil || refreshed.RefreshToken == "" || refreshed.RefreshToken == loginSession.RefreshToken || !refreshed.MustChangePassword ||
		!slices.Contains(refreshed.Permissions, "identity.users.read") ||
		repository.refreshes[0].RevokedAt == "" || repository.refreshes[0].ReplacedByID == "" {
		t.Fatalf("refresh status=%d session=%#v refreshes=%#v body=%s", refreshResponse.Code, refreshed, repository.refreshes, refreshResponse.Body.String())
	}
	if cookies := refreshResponse.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Fatalf("refresh must not create a shared browser cookie: %v", cookies)
	}

	logoutResponse := httptest.NewRecorder()
	handler.authLogout(logoutResponse, httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(`{"workspace_id":"workspace-a","refresh_token":"`+refreshed.RefreshToken+`"}`)))
	if logoutResponse.Code != http.StatusOK || !strings.Contains(logoutResponse.Body.String(), `"ok":true`) || repository.refreshes[len(repository.refreshes)-1].RevokedAt == "" {
		t.Fatalf("logout status=%d refreshes=%#v body=%s", logoutResponse.Code, repository.refreshes, logoutResponse.Body.String())
	}

	guestResponse := httptest.NewRecorder()
	handler.authGuest(guestResponse, surfaceRequest("/auth/guest", `{"workspace_id":"workspace-a"}`, "consumer_portal"))
	if guestResponse.Code != http.StatusOK || !strings.Contains(guestResponse.Body.String(), `"id":"guest_customer"`) || identities.users[len(identities.users)-1].ID != "guest_customer" || identities.assignments[len(identities.assignments)-1].RoleID != "role-customer" {
		t.Fatalf("guest status=%d users=%#v assignments=%#v body=%s", guestResponse.Code, identities.users, identities.assignments, guestResponse.Body.String())
	}
}

func TestRevokeOtherSessionsHandlerIsScopedDurableAndIdempotent(t *testing.T) {
	handler, _, repository, capture, principal := newAuthPasswordHandler(t)
	first, err := handler.passwords.Login(t.Context(), principal.WorkspaceID, principal.UserID, "Password1!")
	if err != nil {
		t.Fatal(err)
	}
	second, err := handler.passwords.Login(t.Context(), principal.WorkspaceID, principal.UserID, "Password1!")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/auth/sessions/revoke-others", nil)
	request.Header.Set("Authorization", "Bearer "+second.AccessToken)
	request.Header.Set("Idempotency-Key", "revoke-others-1")
	response := httptest.NewRecorder()
	handler.authRevokeOtherSessions(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"revoked_sessions":1`) || capture.securityEvent != "auth_other_sessions_revoked" {
		t.Fatalf("status=%d body=%s event=%q data=%v", response.Code, response.Body.String(), capture.securityEvent, capture.securityData)
	}
	if _, err := handler.passwords.VerifyAccessToken(t.Context(), first.AccessToken); apperror.CodeOf(err) != "auth.session_revoked" {
		t.Fatalf("first access token remained valid: %v", err)
	}
	if _, err := handler.passwords.VerifyAccessToken(t.Context(), second.AccessToken); err != nil {
		t.Fatalf("current access token was revoked: %v", err)
	}
	replayRequest := httptest.NewRequest(http.MethodPost, "/auth/sessions/revoke-others", nil)
	replayRequest.Header = request.Header.Clone()
	replay := httptest.NewRecorder()
	handler.authRevokeOtherSessions(replay, replayRequest)
	if replay.Code != http.StatusOK || replay.Header().Get("Idempotency-Replayed") != "true" || !strings.Contains(replay.Body.String(), `"revoked_sessions":1`) {
		t.Fatalf("replay status=%d headers=%v body=%s receipts=%v", replay.Code, replay.Header(), replay.Body.String(), repository.receipts)
	}
}

func TestPasswordLoginAndRefreshAreIndependentOfSurfaceAudience(t *testing.T) {
	handler, _, repository, _, _ := newAuthPasswordHandler(t)
	request := func(path, body string, surface string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("X-Domainry-Product-Surface", surface)
		return req
	}

	loginResponse := httptest.NewRecorder()
	handler.authLogin(loginResponse, request(
		"/auth/login",
		`{"workspace_id":"workspace-a","email":"user@example.com","password":"Password1!"}`,
		"business_workspace",
	))
	var session authmodel.AuthSession
	if loginResponse.Code != http.StatusOK || json.Unmarshal(loginResponse.Body.Bytes(), &session) != nil || session.RefreshToken == "" {
		t.Fatalf("login status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	if len(repository.refreshes) != 1 || repository.refreshes[0].RevokedAt != "" {
		t.Fatalf("authenticated session was revoked by requested Surface: %#v", repository.refreshes)
	}

	handler.roleRequests.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "viewer", Name: "Viewer"}})
	refreshResponse := httptest.NewRecorder()
	handler.authRefresh(refreshResponse, request(
		"/auth/refresh",
		`{"workspace_id":"workspace-a","refresh_token":"`+session.RefreshToken+`"}`,
		"admin_console",
	))
	var refreshed authmodel.AuthSession
	if refreshResponse.Code != http.StatusOK || json.Unmarshal(refreshResponse.Body.Bytes(), &refreshed) != nil || refreshed.RefreshToken == "" {
		t.Fatalf("refresh status=%d body=%s", refreshResponse.Code, refreshResponse.Body.String())
	}
	latest := repository.refreshes[len(repository.refreshes)-1]
	if latest.RevokedAt != "" {
		t.Fatalf("replacement refresh token was revoked by requested Surface: %#v", repository.refreshes)
	}
}

func TestPasswordLoginAcceptsMissingAndUnknownSurfaceContext(t *testing.T) {
	for _, surface := range []string{"", "unknown_surface", "consumer_portal"} {
		t.Run(surface, func(t *testing.T) {
			handler, _, _, _, _ := newAuthPasswordHandler(t)
			request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"workspace_id":"workspace-a","email":"user@example.com","password":"Password1!"}`))
			if surface != "" {
				request.Header.Set("X-Domainry-Product-Surface", surface)
			}
			response := httptest.NewRecorder()
			handler.authLogin(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("Surface %q changed authentication result: status=%d body=%s", surface, response.Code, response.Body.String())
			}
		})
	}
}

func TestPasswordSessionRevocationEdges(t *testing.T) {
	handler, _, _, _, _ := newAuthPasswordHandler(t)
	request := func() *http.Request { return httptest.NewRequest(http.MethodPost, "/auth/login", nil) }
	session := authmodel.AuthSession{WorkspaceID: "workspace-a", User: authmodel.AuthUser{ID: "user-1"}, RefreshToken: "refresh"}
	handler.revokeSession(request(), session)
	externalOnly := *handler
	externalOnly.passwords = nil
	externalOnly.externalAccounts = handler.passwords
	externalOnly.revokeSession(request(), session)
	noSessionService := externalOnly
	noSessionService.externalAccounts = nil
	noSessionService.revokeSession(request(), session)
}

func TestPasswordSessionHandlersRejectInvalidInputsAndAuditLoginFailure(t *testing.T) {
	handler, identities, repository, capture, _ := newAuthPasswordHandler(t)

	handlers := map[string]func(http.ResponseWriter, *http.Request){
		"login": handler.authLogin, "guest": handler.authGuest, "refresh": handler.authRefresh, "logout": handler.authLogout,
	}
	for name, handle := range handlers {
		t.Run(name+" bad JSON", func(t *testing.T) {
			response := httptest.NewRecorder()
			handle(response, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{")))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d", response.Code)
			}
		})
	}

	for name, handle := range handlers {
		t.Run(name+" missing workspace", func(t *testing.T) {
			capture.errorCode = ""
			response := httptest.NewRecorder()
			handle(response, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
			if response.Code != http.StatusBadRequest || capture.errorCode != "backend.workspace_scope_required" {
				t.Fatalf("status=%d code=%q", response.Code, capture.errorCode)
			}
		})
	}

	failedLogin := httptest.NewRecorder()
	handler.authLogin(failedLogin, httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"workspace_id":"workspace-a","user_id":"user-1","password":"wrong"}`)))
	if failedLogin.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil || capture.securityEvent != "auth_login_failed" || capture.securityData["login"] != "user-1" || repository.credential.FailedLoginCount != 1 {
		t.Fatalf("failed login status=%d error=%v event=%q data=%#v credential=%#v", failedLogin.Code, capture.serviceErr, capture.securityEvent, capture.securityData, repository.credential)
	}

	identities.roles = identities.roles[:1]
	capture.serviceErr = nil
	guestFailure := httptest.NewRecorder()
	handler.authGuest(guestFailure, httptest.NewRequest(http.MethodPost, "/auth/guest", strings.NewReader(`{"workspace_id":"workspace-a"}`)))
	if guestFailure.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil {
		t.Fatalf("guest failure status=%d error=%v", guestFailure.Code, capture.serviceErr)
	}

	repository.refreshErr = errors.New("refresh store failed")
	capture.serviceErr = nil
	refreshFailure := httptest.NewRecorder()
	handler.authRefresh(refreshFailure, httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(`{"workspace_id":"workspace-a","refresh_token":"token"}`)))
	if refreshFailure.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil {
		t.Fatalf("refresh failure status=%d error=%v", refreshFailure.Code, capture.serviceErr)
	}
}

func TestPasswordMutationHandlersAuthorizationIdempotencyAndReplay(t *testing.T) {
	handler, _, repository, capture, principal := newAuthPasswordHandler(t)

	*principal = identitymodel.Principal{}
	unauthorized := httptest.NewRecorder()
	handler.authChangePassword(unauthorized, httptest.NewRequest(http.MethodPost, "/auth/password", strings.NewReader(`{}`)))
	if unauthorized.Code != http.StatusUnauthorized || capture.errorCode != "auth.token_required" {
		t.Fatalf("unauthorized status=%d code=%q", unauthorized.Code, capture.errorCode)
	}

	*principal = identitymodel.Principal{Known: true, WorkspaceID: "workspace-a", UserID: "user-1", Role: identitymodel.RoleSchema{Key: "viewer"}}
	badJSON := httptest.NewRecorder()
	handler.authChangePassword(badJSON, httptest.NewRequest(http.MethodPost, "/auth/password", strings.NewReader("{")))
	if badJSON.Code != http.StatusBadRequest {
		t.Fatalf("change bad JSON status=%d", badJSON.Code)
	}
	missingKey := httptest.NewRecorder()
	handler.authChangePassword(missingKey, httptest.NewRequest(http.MethodPost, "/auth/password", strings.NewReader(`{"current_password":"Password1!","new_password":"Password2!"}`)))
	if missingKey.Code != http.StatusBadRequest || capture.errorCode != idempotency.ErrorCodeMissingKey {
		t.Fatalf("missing key status=%d code=%q", missingKey.Code, capture.errorCode)
	}

	changeRequest := func(key, current, next string) *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/auth/password", strings.NewReader(`{"current_password":"`+current+`","new_password":"`+next+`"}`))
		request.Header.Set("Idempotency-Key", key)
		return request
	}
	changed := httptest.NewRecorder()
	handler.authChangePassword(changed, changeRequest("change-1", "Password1!", "Password2!"))
	var changedSession authmodel.AuthSession
	if changed.Code != http.StatusOK || json.Unmarshal(changed.Body.Bytes(), &changedSession) != nil || changedSession.AccessToken == "" || changedSession.RefreshToken == "" || changedSession.MustChangePassword ||
		!slices.Contains(changedSession.Permissions, "identity.users.read") ||
		changed.Header().Get("Idempotency-Replayed") != "" || bcrypt.CompareHashAndPassword([]byte(repository.credential.PasswordHash), []byte("Password2!")) != nil {
		t.Fatalf("change status=%d replay=%q credential=%#v body=%s", changed.Code, changed.Header().Get("Idempotency-Replayed"), repository.credential, changed.Body.String())
	}
	replayed := httptest.NewRecorder()
	handler.authChangePassword(replayed, changeRequest("change-1", "Password1!", "Password2!"))
	var replayedSession authmodel.AuthSession
	if replayed.Code != http.StatusOK || json.Unmarshal(replayed.Body.Bytes(), &replayedSession) != nil || replayedSession.RefreshToken == "" || replayedSession.RefreshToken == changedSession.RefreshToken || replayedSession.MustChangePassword || replayed.Header().Get("Idempotency-Replayed") != "true" || repository.refreshes[len(repository.refreshes)-2].RevokedAt == "" {
		t.Fatalf("replay status=%d replay=%q body=%s", replayed.Code, replayed.Header().Get("Idempotency-Replayed"), replayed.Body.String())
	}

	terminalFailure := httptest.NewRecorder()
	handler.authChangePassword(terminalFailure, changeRequest("change-failed", "wrong", "Password3!"))
	if terminalFailure.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil {
		t.Fatalf("terminal failure status=%d error=%v", terminalFailure.Code, capture.serviceErr)
	}
	failedReplay := httptest.NewRecorder()
	handler.authChangePassword(failedReplay, changeRequest("change-failed", "wrong", "Password3!"))
	if failedReplay.Code != http.StatusUnprocessableEntity || failedReplay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("failed replay status=%d replay=%q error=%v", failedReplay.Code, failedReplay.Header().Get("Idempotency-Replayed"), capture.serviceErr)
	}
}

func TestResetPasswordHandlerAuthorizationValidationAndReplay(t *testing.T) {
	handler, _, repository, capture, principal := newAuthPasswordHandler(t)
	resetRequest := func(key, password string) *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader(`{"user_id":"user-1","new_password":"`+password+`","must_change_password":true}`))
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		return request
	}

	*principal = identitymodel.Principal{}
	unauthorized := httptest.NewRecorder()
	handler.authResetPassword(unauthorized, resetRequest("reset-1", "Password4!"))
	if unauthorized.Code != http.StatusUnauthorized || capture.errorCode != "auth.token_required" {
		t.Fatalf("unauthorized status=%d code=%q", unauthorized.Code, capture.errorCode)
	}
	*principal = identitymodel.Principal{Known: true, WorkspaceID: "workspace-a", UserID: "user-1", Role: identitymodel.RoleSchema{Key: "viewer"}}
	forbidden := httptest.NewRecorder()
	handler.authResetPassword(forbidden, resetRequest("reset-1", "Password4!"))
	if forbidden.Code != http.StatusForbidden || capture.errorCode != "auth.permission_denied" {
		t.Fatalf("forbidden status=%d code=%q", forbidden.Code, capture.errorCode)
	}

	principal.Role.Permissions = []string{"identity.security.write"}
	badJSON := httptest.NewRecorder()
	handler.authResetPassword(badJSON, httptest.NewRequest(http.MethodPost, "/auth/password/reset", strings.NewReader("{")))
	if badJSON.Code != http.StatusBadRequest {
		t.Fatalf("reset bad JSON status=%d", badJSON.Code)
	}
	missingKey := httptest.NewRecorder()
	handler.authResetPassword(missingKey, resetRequest("", "Password4!"))
	if missingKey.Code != http.StatusBadRequest || capture.errorCode != idempotency.ErrorCodeMissingKey {
		t.Fatalf("missing key status=%d code=%q", missingKey.Code, capture.errorCode)
	}

	reset := httptest.NewRecorder()
	handler.authResetPassword(reset, resetRequest("reset-1", "Password4!"))
	if reset.Code != http.StatusOK || repository.credential.MustChangePassword != true || bcrypt.CompareHashAndPassword([]byte(repository.credential.PasswordHash), []byte("Password4!")) != nil {
		t.Fatalf("reset status=%d credential=%#v body=%s", reset.Code, repository.credential, reset.Body.String())
	}
	replay := httptest.NewRecorder()
	handler.authResetPassword(replay, resetRequest("reset-1", "Password4!"))
	if replay.Code != http.StatusOK || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("reset replay status=%d replay=%q body=%s", replay.Code, replay.Header().Get("Idempotency-Replayed"), replay.Body.String())
	}

	principal.WorkspaceID = ""
	capture.serviceErr = nil
	invalidScope := httptest.NewRecorder()
	handler.authResetPassword(invalidScope, resetRequest("reset-invalid-scope", "Password5!"))
	if invalidScope.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil {
		t.Fatalf("invalid scope status=%d error=%v", invalidScope.Code, capture.serviceErr)
	}
}
