// Auth-provider flow domain service tests.
package service

import authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"errors"
	"net/url"
	"testing"
)

type authProviderCallbackAdapterProbe struct {
	called bool
	input  authmodel.AuthProviderCallbackInput
}

func TestOAuth2StartAdaptsWeChatClientParameterWithoutWeakeningState(t *testing.T) {
	auth := NewAuthDomainService(nil, nil, "secret", "", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
	providers := NewAuthProviderDomainService([]map[string]any{{"key": "wechat_web", "type": "oauth2", "adapter": "wechat_web", "enabled": true, "auth_url": "https://open.weixin.qq.com/connect/oauth2/authorize", "client_id": "app-id", "redirect_url": "https://app/callback", "scope": "snsapi_userinfo"}}, false)
	started, err := NewAuthProviderFlowDomainService(auth, providers).Start(t.Context(), "workspace-primary", "wechat_web", "GET", "")
	parsed, parseErr := url.Parse(started.AuthURL)
	if err != nil || parseErr != nil || parsed.Query().Get("appid") != "app-id" || parsed.Query().Get("client_id") != "" || parsed.Query().Get("state") == "" || parsed.Fragment != "wechat_redirect" {
		t.Fatalf("started=%#v parsed=%#v err=%v parseErr=%v", started, parsed, err, parseErr)
	}
}

func (p *authProviderCallbackAdapterProbe) Exchange(_ context.Context, _ string, _ authmodel.AuthProviderConfig, _ authmodel.AuthProviderChallenge, input authmodel.AuthProviderCallbackInput) (authmodel.AuthExternalIdentityAssertion, error) {
	p.called, p.input = true, input
	return authmodel.AuthExternalIdentityAssertion{}, errors.New("exchange stopped")
}

func TestAuthProviderFlowServiceOwnsStartDispatchAndChallengeState(t *testing.T) {
	auth := NewAuthDomainService(nil, nil, "secret", "", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
	providers := NewAuthProviderDomainService([]map[string]any{{"key": "oidc", "type": "oidc", "enabled": true, "auth_url": "https://id.example/auth", "client_id": "client", "redirect_url": "https://app.example/callback", "scope": "openid"}, {"key": "otp", "type": "otp", "enabled": true, "otp_provider": "mock"}, {"key": "disabled", "type": "oidc", "enabled": false}}, false)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	started, err := flows.Start(t.Context(), "workspace-primary", "oidc", "GET", "")
	if err != nil || started.State == "" || started.AuthURL == "" {
		t.Fatalf("oidc start=%#v err=%v", started, err)
	}
	config, challenge, err := flows.ConsumeCallbackChallenge(t.Context(), "workspace-primary", "oidc", started.State)
	if err != nil || config.Key != "oidc" || challenge.Provider != "oidc" {
		t.Fatalf("challenge=%#v config=%#v err=%v", challenge, config, err)
	}
	otp, err := flows.Start(t.Context(), "workspace-primary", "otp", "POST", "10000000002")
	if err != nil || otp.State == "" || otp.Code == "" {
		t.Fatalf("otp start=%#v err=%v", otp, err)
	}
	if _, err := flows.Start(t.Context(), "workspace-primary", "otp", "GET", ""); authProviderTestErrorCode(err) != "auth.provider_start_requires_post" {
		t.Fatalf("otp method err=%v", err)
	}
	if _, err := flows.Start(t.Context(), "workspace-primary", "disabled", "GET", ""); authProviderTestErrorCode(err) != "auth.provider_not_configured" {
		t.Fatalf("disabled err=%v", err)
	}
}

func TestAuthProviderFlowUsesNeutralCallbackAdapterAfterConsumingState(t *testing.T) {
	auth := NewAuthDomainService(nil, nil, "secret", "", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
	providers := NewAuthProviderDomainService([]map[string]any{{"key": "oidc", "type": "oidc", "enabled": true, "auth_url": "https://id.example/auth", "client_id": "client", "redirect_url": "https://app.example/callback"}}, false)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	started, err := flows.Start(t.Context(), "workspace-primary", "oidc", "GET", "")
	if err != nil {
		t.Fatal(err)
	}
	probe := &authProviderCallbackAdapterProbe{}
	input := authmodel.AuthProviderCallbackInput{Method: "POST", Values: map[string]string{"code": "code-1"}}
	if _, err := flows.ExchangeAndCompleteCallback(t.Context(), "workspace-primary", "oidc", started.State, input, probe); err == nil || !probe.called || probe.input.Values["code"] != "code-1" {
		t.Fatalf("adapter called=%v input=%#v err=%v", probe.called, probe.input, err)
	}
	if _, _, err := flows.ConsumeCallbackChallenge(t.Context(), "workspace-primary", "oidc", started.State); authProviderTestErrorCode(err) != "auth.provider_state_invalid" {
		t.Fatalf("callback state was not consumed once: %v", err)
	}
}

func TestOTPChallengeCannotBeConsumedOrInvalidatedAcrossWorkspaces(t *testing.T) {
	auth := NewAuthDomainService(nil, nil, "secret", "", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
	started, err := auth.BeginOTPLogin(t.Context(), "workspace-a", "otp", "+10000000002")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ConsumeOTPChallenge(t.Context(), "workspace-b", "otp", started.State, started.Code); authProviderTestErrorCode(err) != "auth.provider_state_invalid" {
		t.Fatalf("cross-workspace consume error=%v", err)
	}
	assertion, err := auth.ConsumeOTPChallenge(t.Context(), "workspace-a", "otp", started.State, started.Code)
	if err != nil || assertion.Phone != "+10000000002" || assertion.Email != "10000000002@otp.identity.invalid" || assertion.DisplayName != "+10000000002" {
		t.Fatalf("workspace A challenge was invalidated: assertion=%#v err=%v", assertion, err)
	}
}

func authProviderTestErrorCode(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
