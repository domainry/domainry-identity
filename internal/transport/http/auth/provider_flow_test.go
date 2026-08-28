package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authprojection "github.com/domainry/domainry-identity/internal/domain/auth/projection"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type authProviderCallbackStub struct {
	assertion authmodel.AuthExternalIdentityAssertion
	err       error
	called    int
	provider  string
	config    authmodel.AuthProviderConfig
	challenge authmodel.AuthProviderChallenge
	input     authmodel.AuthProviderCallbackInput
}

func (s *authProviderCallbackStub) ExchangeCode(_ context.Context, provider string, config authmodel.AuthProviderConfig, code string) (authmodel.AuthExternalIdentityAssertion, error) {
	s.called++
	s.provider, s.config = provider, config
	s.input = authmodel.AuthProviderCallbackInput{Method: http.MethodPost, Values: map[string]string{"code": code}}
	return s.assertion, s.err
}

func (s *authProviderCallbackStub) Exchange(_ context.Context, provider string, config authmodel.AuthProviderConfig, challenge authmodel.AuthProviderChallenge, input authmodel.AuthProviderCallbackInput) (authmodel.AuthExternalIdentityAssertion, error) {
	s.called++
	s.provider, s.config, s.challenge, s.input = provider, config, challenge, input
	return s.assertion, s.err
}

type authProviderFlowStub struct {
	startResult       authprojection.AuthProviderStartResponse
	startErr          error
	verifyResult      authmodel.AuthSession
	verifyErr         error
	callbackResult    authmodel.AuthSession
	callbackChallenge authmodel.AuthProviderChallenge
	callbackErr       error
}

func (s authProviderFlowStub) Start(context.Context, string, string, string, string) (authprojection.AuthProviderStartResponse, error) {
	return s.startResult, s.startErr
}
func (s authProviderFlowStub) VerifyOTP(context.Context, string, string, string, string) (authmodel.AuthSession, error) {
	return s.verifyResult, s.verifyErr
}
func (s authProviderFlowStub) ExchangeAndCompleteCallbackWithChallenge(context.Context, string, string, authmodel.AuthProviderCallbackInput, authcontract.AuthProviderCallbackAdapter) (authmodel.AuthSession, authmodel.AuthProviderChallenge, error) {
	return s.callbackResult, s.callbackChallenge, s.callbackErr
}

type authProviderFlowFixture struct {
	handler       *AuthHandler
	repository    *authPasswordRepository
	capture       *authExternalHandlerCapture
	callback      *authProviderCallbackStub
	failureEvent  string
	failureReason string
}

func newAuthProviderFlowFixture(t *testing.T) *authProviderFlowFixture {
	t.Helper()
	handler, _, repository, capture, _ := newAuthPasswordHandler(t)
	repository.accounts = []identitymodel.IdentityExternalAccount{
		{ID: "otp-account", UserID: "user-1", Provider: "whatsapp", ProviderSubject: "+8613800000000"},
		{ID: "oidc-account", UserID: "user-1", Provider: "oidc", ProviderSubject: "oidc-user"},
		{ID: "wechat-account", UserID: "user-1", Provider: "wechat_mini_program", ProviderSubject: "wechat-user"},
		{ID: "line-account", UserID: "user-1", Provider: "line", ProviderSubject: "line-user"},
	}
	providers := authapplication.NewAuthProviderApplicationService([]map[string]any{
		{"key": "oidc", "type": "oidc", "enabled": true, "auth_url": "https://identity.example/authorize", "client_id": "client-1", "redirect_url": "https://app.example/callback", "scope": "openid", "auto_create_users": false},
		{"key": "whatsapp", "type": "otp", "enabled": true, "otp_provider": "mock", "auto_create_users": false},
		{"key": "unsupported", "type": "custom", "enabled": true},
		{"key": "disabled", "type": "oidc", "enabled": false},
		{"key": "wechat_mini_program", "type": "wechat_mini_program", "enabled": true, "client_id": "app", "client_secret": "secret", "auto_create_users": false},
		{"key": "line", "type": "code_exchange", "adapter": "line_liff", "enabled": true, "client_id": "channel", "auto_create_users": true, "default_role_key": "member_onboarding"},
	}, false, nil)
	flows := authapplication.NewAuthProviderFlowApplicationService(handler.passwords, providers)
	callback := &authProviderCallbackStub{assertion: authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "oidc-user"}}
	fixture := &authProviderFlowFixture{handler: handler, repository: repository, capture: capture, callback: callback}
	handler.providerFlows = flows
	handler.providerCallback = callback
	handler.providerFailureAudit = func(_ *http.Request, provider, reason string) {
		fixture.failureEvent, fixture.failureReason = provider, reason
	}
	return fixture
}

func TestAuthProviderExchangeAcceptsLineLIFFIDToken(t *testing.T) {
	fixture := newAuthProviderFlowFixture(t)
	fixture.callback.assertion = authmodel.AuthExternalIdentityAssertion{Provider: "line", Subject: "line-user", ProviderSubjectVerified: true}
	request := providerFlowRequest(http.MethodPost, "/auth/providers/line/exchange", "line", `{"workspace_id":"workspace-a","application_key":"line-mini","id_token":"liff-id-token"}`)
	response := httptest.NewRecorder()
	fixture.handler.authProviderExchange(response, request)
	if session := decodeProviderFlowSession(t, response); response.Code != http.StatusOK || session.User.ID != "user-1" || fixture.callback.input.Values["code"] != "liff-id-token" {
		t.Fatalf("status=%d session=%#v callback=%#v body=%s", response.Code, session, fixture.callback, response.Body.String())
	}
}

func TestAuthProviderExchangeCompletesWeChatMiniProgramLogin(t *testing.T) {
	fixture := newAuthProviderFlowFixture(t)
	fixture.callback.assertion = authmodel.AuthExternalIdentityAssertion{Provider: "wechat_mini_program", Subject: "wechat-user"}
	request := providerFlowRequest(http.MethodPost, "/auth/providers/wechat_mini_program/exchange", "wechat_mini_program", `{"workspace_id":"workspace-a","application_key":"mini-app","code":"wx-code"}`)
	response := httptest.NewRecorder()
	fixture.handler.authProviderExchange(response, request)
	if session := decodeProviderFlowSession(t, response); response.Code != http.StatusOK || session.User.ID != "user-1" || fixture.callback.input.Values["code"] != "wx-code" {
		t.Fatalf("status=%d session=%#v callback=%#v body=%s", response.Code, session, fixture.callback, response.Body.String())
	}

	unsupported := httptest.NewRecorder()
	fixture.handler.authProviderExchange(unsupported, providerFlowRequest(http.MethodPost, "/", "oidc", `{"workspace_id":"workspace-a","code":"code"}`))
	if unsupported.Code != http.StatusUnprocessableEntity || fixture.capture.serviceErr == nil {
		t.Fatalf("unsupported status=%d error=%v", unsupported.Code, fixture.capture.serviceErr)
	}
}

func providerFlowRequest(method, target, provider, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.SetPathValue("provider", provider)
	request.Header.Set("X-Domainry-Product-Surface", "admin_console")
	return request
}

func decodeProviderFlowSession(t *testing.T, response *httptest.ResponseRecorder) authmodel.AuthSession {
	t.Helper()
	var session authmodel.AuthSession
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatalf("decode session: %v body=%s", err, response.Body.String())
	}
	return session
}

func startProviderFlow(t *testing.T, fixture *authProviderFlowFixture, provider string, body string) map[string]any {
	t.Helper()
	response := httptest.NewRecorder()
	fixture.handler.authProviderStart(response, providerFlowRequest(http.MethodPost, "/auth/providers/"+provider+"/start", provider, body))
	if response.Code != http.StatusOK {
		t.Fatalf("start %s status=%d error=%v body=%s", provider, response.Code, fixture.capture.serviceErr, response.Body.String())
	}
	result := map[string]any{}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode start %s: %v", provider, err)
	}
	return result
}

func TestAuthProviderStartSupportsOIDCOTPAndRejectsInvalidRequests(t *testing.T) {
	fixture := newAuthProviderFlowFixture(t)

	oidcResponse := httptest.NewRecorder()
	fixture.handler.authProviderStart(oidcResponse, providerFlowRequest(http.MethodGet, "/auth/providers/oidc/start?workspace_id=workspace-a", " oidc ", ""))
	if oidcResponse.Code != http.StatusOK || !strings.Contains(oidcResponse.Body.String(), `"provider":"oidc"`) || !strings.Contains(oidcResponse.Body.String(), "identity.example") || !strings.Contains(oidcResponse.Body.String(), `"state":`) {
		t.Fatalf("OIDC status=%d body=%s", oidcResponse.Code, oidcResponse.Body.String())
	}

	otp := startProviderFlow(t, fixture, "whatsapp", `{"workspace_id":"workspace-a","phone":"+8613800000000"}`)
	if otp["provider"] != "whatsapp" || strings.TrimSpace(stringFromAny(otp["state"])) == "" || len(stringFromAny(otp["code"])) != 6 {
		t.Fatalf("OTP start = %#v", otp)
	}

	badJSON := httptest.NewRecorder()
	fixture.handler.authProviderStart(badJSON, providerFlowRequest(http.MethodPost, "/", "whatsapp", "{"))
	if badJSON.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON status=%d", badJSON.Code)
	}
	missingWorkspace := httptest.NewRecorder()
	fixture.handler.authProviderStart(missingWorkspace, providerFlowRequest(http.MethodGet, "/", "oidc", ""))
	if missingWorkspace.Code != http.StatusBadRequest || fixture.capture.errorCode != "backend.workspace_scope_required" {
		t.Fatalf("missing workspace status=%d code=%q", missingWorkspace.Code, fixture.capture.errorCode)
	}
	for _, provider := range []string{"disabled", "unsupported"} {
		fixture.capture.serviceErr = nil
		response := httptest.NewRecorder()
		fixture.handler.authProviderStart(response, providerFlowRequest(http.MethodGet, "/?workspace_id=workspace-a", provider, ""))
		if response.Code != http.StatusUnprocessableEntity || fixture.capture.serviceErr == nil {
			t.Fatalf("provider=%s status=%d error=%v", provider, response.Code, fixture.capture.serviceErr)
		}
	}
}

func TestAuthProviderStartAllowsNilAndEmptyPostBodies(t *testing.T) {
	for _, nilBody := range []bool{true, false} {
		fixture := newAuthProviderFlowFixture(t)
		request := providerFlowRequest(http.MethodPost, "/auth/providers/oidc/start?workspace_id=workspace-a", "oidc", "")
		if nilBody {
			request.Body = nil
		}
		response := httptest.NewRecorder()
		fixture.handler.authProviderStart(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("nilBody=%v status=%d error=%v body=%s", nilBody, response.Code, fixture.capture.serviceErr, response.Body.String())
		}
	}
}

func TestAuthProviderVerifyCoversSuccessStateAndExternalLoginFailures(t *testing.T) {
	fixture := newAuthProviderFlowFixture(t)
	otp := startProviderFlow(t, fixture, "whatsapp", `{"workspace_id":"workspace-a","phone":"+8613800000000"}`)
	body := `{"workspace_id":"workspace-a","state":"` + stringFromAny(otp["state"]) + `","code":"` + stringFromAny(otp["code"]) + `"}`
	surfaceRequest := providerFlowRequest(http.MethodPost, "/", "whatsapp", body)
	surfaceRequest.Header.Set("X-Domainry-Product-Surface", "consumer_portal")
	success := httptest.NewRecorder()
	fixture.handler.authProviderVerify(success, surfaceRequest)
	if session := decodeProviderFlowSession(t, success); success.Code != http.StatusOK || session.User.ID != "user-1" || session.RefreshToken == "" {
		t.Fatalf("verify must ignore Surface status=%d session=%#v body=%s", success.Code, session, success.Body.String())
	}

	badJSON := httptest.NewRecorder()
	fixture.handler.authProviderVerify(badJSON, providerFlowRequest(http.MethodPost, "/", "whatsapp", "{"))
	if badJSON.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON status=%d", badJSON.Code)
	}
	missingWorkspace := httptest.NewRecorder()
	fixture.handler.authProviderVerify(missingWorkspace, providerFlowRequest(http.MethodPost, "/", "whatsapp", `{}`))
	if missingWorkspace.Code != http.StatusBadRequest || fixture.capture.errorCode != "backend.workspace_scope_required" {
		t.Fatalf("missing workspace status=%d code=%q", missingWorkspace.Code, fixture.capture.errorCode)
	}

	invalidState := httptest.NewRecorder()
	fixture.handler.authProviderVerify(invalidState, providerFlowRequest(http.MethodPost, "/", "whatsapp", `{"workspace_id":"workspace-a","state":"missing","code":"000000"}`))
	if invalidState.Code != http.StatusForbidden || fixture.capture.errorCode != "auth.provider_state_invalid" || fixture.failureEvent != "whatsapp" || fixture.failureReason != "otp_verify" {
		t.Fatalf("invalid state status=%d code=%q audit=%q/%q", invalidState.Code, fixture.capture.errorCode, fixture.failureEvent, fixture.failureReason)
	}

	unlinked := startProviderFlow(t, fixture, "whatsapp", `{"workspace_id":"workspace-a","phone":"+8613900000000"}`)
	unlinkedBody := `{"workspace_id":"workspace-a","state":"` + stringFromAny(unlinked["state"]) + `","code":"` + stringFromAny(unlinked["code"]) + `"}`
	unlinkedResponse := httptest.NewRecorder()
	fixture.handler.authProviderVerify(unlinkedResponse, providerFlowRequest(http.MethodPost, "/", "whatsapp", unlinkedBody))
	if unlinkedResponse.Code != http.StatusForbidden || fixture.capture.errorCode != "auth.external_account_unlinked" || fixture.failureReason != "external_login" {
		t.Fatalf("unlinked status=%d code=%q audit=%q", unlinkedResponse.Code, fixture.capture.errorCode, fixture.failureReason)
	}
}

func TestAuthProviderCallbackCompletesGETAndPOSTRelayState(t *testing.T) {
	fixture := newAuthProviderFlowFixture(t)
	started := startProviderFlow(t, fixture, "oidc", `{"workspace_id":"workspace-a"}`)
	state := url.QueryEscape(stringFromAny(started["state"]))
	getResponse := httptest.NewRecorder()
	getRequest := providerFlowRequest(http.MethodGet, "/callback?state="+state+"&code=code-1", " oidc ", "")
	getRequest.Header.Del("X-Domainry-Product-Surface")
	fixture.handler.authProviderCallback(getResponse, getRequest)
	if session := decodeProviderFlowSession(t, getResponse); getResponse.Code != http.StatusOK || session.User.ID != "user-1" || fixture.callback.called != 1 || fixture.callback.provider != "oidc" || fixture.callback.input.Method != http.MethodGet || fixture.callback.input.Values["code"] != "code-1" || fixture.callback.challenge.WorkspaceID != "workspace-a" {
		t.Fatalf("GET callback status=%d session=%#v callback=%#v", getResponse.Code, session, fixture.callback)
	}

	started = startProviderFlow(t, fixture, "oidc", `{"workspace_id":"workspace-a"}`)
	form := url.Values{"RelayState": {stringFromAny(started["state"])}, "SAMLResponse": {"assertion"}}
	postRequest := providerFlowRequest(http.MethodPost, "/callback?query=value", "oidc", form.Encode())
	postRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postResponse := httptest.NewRecorder()
	fixture.handler.authProviderCallback(postResponse, postRequest)
	if postResponse.Code != http.StatusOK || fixture.callback.called != 2 || fixture.callback.input.Method != http.MethodPost || fixture.callback.input.Values["RelayState"] == "" || fixture.callback.input.Values["SAMLResponse"] != "assertion" || fixture.callback.input.Values["query"] != "value" {
		t.Fatalf("POST callback status=%d callback=%#v body=%s", postResponse.Code, fixture.callback, postResponse.Body.String())
	}
}

func TestAuthProviderCallbackMapsConfigurationStateExchangeAndLoginErrors(t *testing.T) {
	fixture := newAuthProviderFlowFixture(t)

	for provider, wantCode := range map[string]string{"missing": "auth.provider_not_configured", "whatsapp": "auth.provider_callback_not_supported"} {
		fixture.capture.serviceErr = nil
		response := httptest.NewRecorder()
		fixture.handler.authProviderCallback(response, providerFlowRequest(http.MethodGet, "/callback?state=state", provider, ""))
		if response.Code != http.StatusUnprocessableEntity || fixture.capture.serviceErr == nil || !strings.Contains(fixture.capture.serviceErr.Error(), wantCode) {
			t.Fatalf("provider=%s status=%d error=%v", provider, response.Code, fixture.capture.serviceErr)
		}
	}

	invalidState := httptest.NewRecorder()
	fixture.handler.authProviderCallback(invalidState, providerFlowRequest(http.MethodGet, "/callback?state=missing", "oidc", ""))
	if invalidState.Code != http.StatusForbidden || fixture.capture.errorCode != "auth.provider_state_invalid" || fixture.failureReason != "state" {
		t.Fatalf("invalid state status=%d code=%q audit=%q", invalidState.Code, fixture.capture.errorCode, fixture.failureReason)
	}

	for name, test := range map[string]struct {
		err       error
		status    int
		code      string
		auditKind string
	}{
		"exchange": {err: errors.New("token_exchange unavailable"), status: http.StatusBadGateway, code: "auth.provider_token_exchange_not_configured", auditKind: "token_exchange"},
		"login":    {err: errors.New("assertion rejected"), status: http.StatusForbidden, code: "auth.external_account_unlinked", auditKind: "external_login"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture.callback.err = test.err
			started := startProviderFlow(t, fixture, "oidc", `{"workspace_id":"workspace-a"}`)
			response := httptest.NewRecorder()
			fixture.handler.authProviderCallback(response, providerFlowRequest(http.MethodGet, "/callback?state="+url.QueryEscape(stringFromAny(started["state"])), "oidc", ""))
			if response.Code != test.status || fixture.capture.errorCode != test.code || fixture.failureReason != test.auditKind {
				t.Fatalf("status=%d code=%q audit=%q", response.Code, fixture.capture.errorCode, fixture.failureReason)
			}
		})
	}
}

func TestAuthProviderFlowIsIndependentOfSurface(t *testing.T) {
	fixture := newAuthProviderFlowFixture(t)

	invalidStartRequest := providerFlowRequest(http.MethodGet, "/?workspace_id=workspace-a", "oidc", "")
	invalidStartRequest.Header.Set("X-Domainry-Product-Surface", "invalid")
	invalidStart := httptest.NewRecorder()
	fixture.handler.authProviderStart(invalidStart, invalidStartRequest)
	if invalidStart.Code != http.StatusOK {
		t.Fatalf("provider start must ignore Surface status=%d code=%q", invalidStart.Code, fixture.capture.errorCode)
	}
}

func TestCallbackInputProjectsQueryAndPostForm(t *testing.T) {
	get := callbackInput(httptest.NewRequest(http.MethodGet, "/callback?state=one&state=two&code=code-1", nil))
	if get.Method != http.MethodGet || get.Values["state"] != "one" || get.Values["code"] != "code-1" {
		t.Fatalf("GET input = %#v", get)
	}
	request := httptest.NewRequest(http.MethodPost, "/callback?query=value", strings.NewReader("state=form-state&code=form-code"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post := callbackInput(request)
	if post.Method != http.MethodPost || post.Values["query"] != "value" || post.Values["state"] != "form-state" || post.Values["code"] != "form-code" {
		t.Fatalf("POST input = %#v", post)
	}
}
