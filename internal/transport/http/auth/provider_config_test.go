package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type authProviderWriterStub struct {
	credential authmodel.AuthProviderCredential
	err        error
	calls      int
	provider   string
	request    authmodel.AuthProviderCredentialUpsertRequest
}

func (w *authProviderWriterStub) UpsertAuthProviderCredential(_ context.Context, provider string, request authmodel.AuthProviderCredentialUpsertRequest, _ identitymodel.Principal) (authmodel.AuthProviderCredential, error) {
	w.calls++
	w.provider, w.request = provider, request
	return w.credential, w.err
}

type authProviderHandlerCapture struct {
	serviceErr error
	errorCode  string
}

func newAuthProviderHandler(t *testing.T, writer *authProviderWriterStub) (*AuthHandler, *authProviderHandlerCapture) {
	t.Helper()
	configs := []map[string]any{
		{"key": "feishu", "label": "Feishu", "type": "oidc", "enabled": true, "client_id": "mock-app", "client_secret": "mock-secret", "client_secret_configured": true, "redirect_url": "https://app.example/auth/callback", "scope": "openid"},
		{"key": "github", "label": "GitHub", "type": "oidc", "enabled": true, "client_id": "github-client", "client_secret": "github-secret", "client_secret_configured": true, "redirect_url": "https://app.example/github/callback"},
		{"key": "disabled", "label": "Disabled", "type": "oidc", "enabled": false},
	}
	service := authapplication.NewAuthProviderApplicationService(configs, true, writer)
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-a", UserID: "admin", Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "auth.providers.setup")}}
	capture := &authProviderHandlerCapture{}
	handler := NewAuthHandler(AuthDependencies{
		ProviderConfiguration: service,
		Principal:             func(*http.Request) identitymodel.Principal { return principal },
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
	})
	return handler, capture
}

func authProviderRequest(method, body, provider string) *http.Request {
	request := httptest.NewRequest(method, "/", strings.NewReader(body))
	request.SetPathValue("provider", provider)
	return request
}

func TestAuthProviderHandlersListCheckAndSaveWithoutLeakingSecrets(t *testing.T) {
	writer := &authProviderWriterStub{credential: authmodel.AuthProviderCredential{ProviderKey: "feishu", Type: "oidc", ClientID: "saved-client", ClientSecret: "saved-secret", RedirectURL: "https://app.example/saved", Scope: "openid", UpdatedAt: "2026-07-19T00:00:00Z"}}
	handler, capture := newAuthProviderHandler(t, writer)

	providersResponse := httptest.NewRecorder()
	handler.authProviders(providersResponse, httptest.NewRequest(http.MethodGet, "/auth/providers", nil))
	if providersResponse.Code != http.StatusOK || strings.Contains(providersResponse.Body.String(), "mock-secret") || strings.Contains(providersResponse.Body.String(), "github-secret") || !strings.Contains(providersResponse.Body.String(), `"feishu"`) {
		t.Fatalf("providers status=%d body=%s", providersResponse.Code, providersResponse.Body.String())
	}

	checkResponse := httptest.NewRecorder()
	handler.authProviderSetupCheck(checkResponse, authProviderRequest(http.MethodGet, "", " feishu "))
	if checkResponse.Code != http.StatusOK || !strings.Contains(checkResponse.Body.String(), `"status":"ok"`) || !strings.Contains(checkResponse.Body.String(), `"mode":"mock"`) || strings.Contains(checkResponse.Body.String(), "mock-secret") {
		t.Fatalf("check status=%d body=%s", checkResponse.Code, checkResponse.Body.String())
	}

	unknownResponse := httptest.NewRecorder()
	handler.authProviderSetupCheck(unknownResponse, authProviderRequest(http.MethodGet, "", "missing"))
	if unknownResponse.Code != http.StatusNotFound || capture.errorCode != "auth.provider_unknown" {
		t.Fatalf("unknown status=%d code=%q", unknownResponse.Code, capture.errorCode)
	}

	badJSONResponse := httptest.NewRecorder()
	handler.authProviderSetupSave(badJSONResponse, authProviderRequest(http.MethodPut, "{", "feishu"))
	if badJSONResponse.Code != http.StatusBadRequest || writer.calls != 0 {
		t.Fatalf("bad JSON status=%d calls=%d", badJSONResponse.Code, writer.calls)
	}

	saveBody := `{"client_id":"saved-client","client_secret":"saved-secret","redirect_url":"https://app.example/saved"}`
	saveResponse := httptest.NewRecorder()
	handler.authProviderSetupSave(saveResponse, authProviderRequest(http.MethodPut, saveBody, " feishu "))
	if saveResponse.Code != http.StatusOK || capture.serviceErr != nil || writer.calls != 1 || writer.provider != "feishu" || writer.request.ClientSecret != "saved-secret" || strings.Contains(saveResponse.Body.String(), "saved-secret") || !strings.Contains(saveResponse.Body.String(), `"effective":true`) {
		t.Fatalf("save status=%d error=%v writer=%#v body=%s", saveResponse.Code, capture.serviceErr, writer, saveResponse.Body.String())
	}

	writer.err = errors.New("credential write failed")
	capture.serviceErr = nil
	failureResponse := httptest.NewRecorder()
	handler.authProviderSetupSave(failureResponse, authProviderRequest(http.MethodPut, saveBody, "feishu"))
	if failureResponse.Code != http.StatusUnprocessableEntity || capture.serviceErr == nil {
		t.Fatalf("save failure status=%d error=%v", failureResponse.Code, capture.serviceErr)
	}
}

func TestAuthProviderSetupResultCoversProviderKindsAndWrappers(t *testing.T) {
	handler, _ := newAuthProviderHandler(t, &authProviderWriterStub{})

	disabled, ok := handler.authProviderConfig(t.Context(), " disabled ")
	if !ok {
		t.Fatal("disabled provider not found")
	}
	disabledResult := handler.authProviderSetupResult(disabled)
	if disabledResult["status"] != "blocked_missing_configuration" || disabledResult["redirect_url"] != "" || disabledResult["scope"] != "" {
		t.Fatalf("disabled result = %#v", disabledResult)
	}

	github, enabled := handler.enabledAuthProvider(t.Context(), " GITHUB ")
	if !enabled || github.Key != "github" {
		t.Fatalf("enabled provider = %#v enabled=%v", github, enabled)
	}
	manual := handler.authProviderSetupResult(github)
	remote := manual["remote_check"].(map[string]any)
	if manual["status"] != "configured_manual_provider_review_required" || remote["status"] != "not_implemented_for_provider" {
		t.Fatalf("manual result = %#v", manual)
	}

	policy := handler.externalLoginPolicy(t.Context(), authmodel.AuthProviderConfig{AutoCreateConfigured: true, AutoCreateUsers: false, DefaultRoleKey: "viewer"})
	if policy.AutoCreateUsers || policy.DefaultRoleKey != "viewer" {
		t.Fatalf("external login policy = %#v", policy)
	}

	otp := authmodel.AuthProviderConfig{Key: "whatsapp", Label: "WhatsApp", Type: "otp", Enabled: true, OTPProvider: "meta", AccessTokenConfigured: true, PhoneNumberIDConfigured: false}
	otpResult := handler.authProviderSetupResult(otp)
	checks := otpResult["checks"].([]map[string]any)
	steps := otpResult["next_steps"].([]string)
	if len(checks) != 3 || checks[0]["ok"] != true || checks[1]["ok"] != true || checks[2]["ok"] != false || len(steps) != 1 || steps[0] != "configure_phone_number_id" {
		t.Fatalf("OTP checks=%#v steps=%#v", checks, steps)
	}
	complete := otp.Map()
	complete["phone_number_id_configured"] = true
	if steps := authProviderSetupNextSteps(complete); len(steps) != 1 || steps[0] != "run_provider_remote_check" {
		t.Fatalf("complete next steps = %#v", steps)
	}
}

func TestCheckFeishuProviderConfigRemoteOutcomes(t *testing.T) {
	originalBuild, originalExecute := buildAuthProviderProbeRequest, executeAuthProviderProbeRequest
	t.Cleanup(func() {
		buildAuthProviderProbeRequest = originalBuild
		executeAuthProviderProbeRequest = originalExecute
	})
	handler, _ := newAuthProviderHandler(t, &authProviderWriterStub{})
	config := map[string]any{"client_id": "live-app", "client_secret": "live-secret", "redirect_url": "https://app.example/callback"}
	if result := handler.checkFeishuProviderConfig(map[string]any{"client_id": "live-app", "client_secret": "mock-secret"}); result["mode"] != "mock" {
		t.Fatalf("mock secret result = %#v", result)
	}

	buildAuthProviderProbeRequest = func(string, string, io.Reader) (*http.Request, error) { return nil, errors.New("build failed") }
	if result := handler.checkFeishuProviderConfig(config); result["reason"] != "build_request_failed" {
		t.Fatalf("build failure = %#v", result)
	}

	buildAuthProviderProbeRequest = originalBuild
	executeAuthProviderProbeRequest = func(*http.Request) (*http.Response, error) { return nil, errors.New("request failed") }
	if result := handler.checkFeishuProviderConfig(config); result["reason"] != "request_failed" {
		t.Fatalf("request failure = %#v", result)
	}

	executeAuthProviderProbeRequest = func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{"))}, nil
	}
	if result := handler.checkFeishuProviderConfig(config); result["reason"] != "decode_failed" || result["http_status"] != http.StatusOK {
		t.Fatalf("decode failure = %#v", result)
	}

	executeAuthProviderProbeRequest = func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(`{"code":1001,"msg":"invalid"}`))}, nil
	}
	if result := handler.checkFeishuProviderConfig(config); result["reason"] != "provider_rejected_credentials" || result["provider_code"] != 1001 {
		t.Fatalf("provider rejection = %#v", result)
	}

	executeAuthProviderProbeRequest = func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusContinue, Body: io.NopCloser(strings.NewReader(`{"code":0,"app_access_token":"token"}`))}, nil
	}
	if result := handler.checkFeishuProviderConfig(config); result["reason"] != "provider_rejected_credentials" {
		t.Fatalf("informational response = %#v", result)
	}

	executeAuthProviderProbeRequest = func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"code":0}`))}, nil
	}
	if result := handler.checkFeishuProviderConfig(config); result["reason"] != "provider_rejected_credentials" {
		t.Fatalf("missing token response = %#v", result)
	}

	executeAuthProviderProbeRequest = func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatalf("content type = %q", request.Header.Get("Content-Type"))
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"code":0,"app_access_token":"token","expire":7200}`))}, nil
	}
	result := handler.checkFeishuProviderConfig(config)
	if result["status"] != "ok" || result["mode"] != "live" || result["app_token_expires_in"] != 7200 || result["can_login"] != true {
		t.Fatalf("live result = %#v", result)
	}
}

func TestAuthProviderConfigValueHelpers(t *testing.T) {
	config := map[string]any{"string": " value ", "bool": true, "wrong_string": 1, "wrong_bool": "true"}
	if stringFromProviderConfig(config, "string") != "value" || stringFromProviderConfig(config, "wrong_string") != "" || !boolFromProviderConfig(config, "bool") || boolFromProviderConfig(config, "wrong_bool") {
		t.Fatalf("provider config helpers returned unexpected values")
	}
	tests := []struct {
		value any
		want  string
	}{
		{value: " text ", want: "text"},
		{value: json.Number("42"), want: "42"},
		{value: float64(42), want: "42"},
		{value: 3.5, want: "3.5"},
		{value: true, want: "true"},
		{value: false, want: "false"},
		{value: nil, want: ""},
	}
	for _, test := range tests {
		if got := stringFromAny(test.value); got != test.want {
			t.Errorf("stringFromAny(%#v)=%q want=%q", test.value, got, test.want)
		}
	}
}
