// Auth-provider flow domain service tests.
package service

import authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"errors"
	"net/url"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
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

func TestFederatedCallbackAutoCreatesAndBindsUnlinkedIdentityInChallengeWorkspace(t *testing.T) {
	auth, identityRepository, authRepository := newFaultAuthDomainService()
	providers := NewAuthProviderDomainService([]map[string]any{{
		"key": "oidc", "type": "oidc", "enabled": true,
		"auth_url": "https://id.example/auth", "client_id": "client", "redirect_url": "https://app.example/callback",
		"auto_create_users": true, "default_role_key": "sales",
	}}, true)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	started, err := flows.Start(t.Context(), "workspace-application", "oidc", "GET", "")
	if err != nil {
		t.Fatal(err)
	}
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "unlinked-subject", Email: "unlinked@example.test", DisplayName: "Unlinked User", ProviderSubjectVerified: true}
	session, err := flows.ExchangeAndCompleteCallback(t.Context(), "workspace-application", "oidc", started.State, authmodel.AuthProviderCallbackInput{}, assertionAdapter{assertion: assertion})
	if err != nil || session.User.Email != assertion.Email || session.User.Name != assertion.DisplayName {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	if len(identityRepository.users) != 1 || len(authRepository.accounts) != 1 || authRepository.accounts[0].UserID != identityRepository.users[0].UserID || authRepository.accounts[0].ProviderSubject != assertion.Subject {
		t.Fatalf("users=%#v accounts=%#v", identityRepository.users, authRepository.accounts)
	}
	if len(identityRepository.roleAssignments) != 1 || identityRepository.roleAssignments[0].UserID != identityRepository.users[0].UserID || identityRepository.roleAssignments[0].RoleID != "role-sales" {
		t.Fatalf("role assignments=%#v", identityRepository.roleAssignments)
	}
}

func TestFederatedCallbackAutoBindsExistingUserByEmail(t *testing.T) {
	auth, identityRepository, authRepository := newFaultAuthDomainService()
	identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("existing-user", "existing@example.test")}
	providers := NewAuthProviderDomainService([]map[string]any{{
		"key": "feishu", "type": "oidc", "enabled": true,
		"auth_url": "https://accounts.feishu.cn/open-apis/authen/v1/authorize", "client_id": "client", "redirect_url": "https://app.example/callback",
		"auto_create_users": true,
	}}, true)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	started, err := flows.Start(t.Context(), "workspace-application", "feishu", "GET", "")
	if err != nil {
		t.Fatal(err)
	}
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "feishu", Subject: "feishu-subject", Email: "existing@example.test", ProviderSubjectVerified: true}
	session, err := flows.ExchangeAndCompleteCallback(t.Context(), "workspace-application", "feishu", started.State, authmodel.AuthProviderCallbackInput{}, assertionAdapter{assertion: assertion})
	if err != nil || session.User.UserID != "existing-user" {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	if len(identityRepository.users) != 1 || len(authRepository.accounts) != 1 || authRepository.accounts[0].UserID != "existing-user" || authRepository.accounts[0].ProviderSubject != assertion.Subject {
		t.Fatalf("users=%#v accounts=%#v", identityRepository.users, authRepository.accounts)
	}
}

func TestFederatedCallbackRejectsUnlinkedIdentityWhenAutoCreateIsDisabled(t *testing.T) {
	auth, identityRepository, authRepository := newFaultAuthDomainService()
	providers := NewAuthProviderDomainService([]map[string]any{{
		"key": "oidc", "type": "oidc", "enabled": true,
		"auth_url": "https://id.example/auth", "client_id": "client", "redirect_url": "https://app.example/callback",
		"auto_create_users": false,
	}}, false)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	started, err := flows.Start(t.Context(), "workspace-application", "oidc", "GET", "")
	if err != nil {
		t.Fatal(err)
	}
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "unlinked-subject", Email: "unlinked@example.test", ProviderSubjectVerified: true}
	if _, err := flows.ExchangeAndCompleteCallback(t.Context(), "workspace-application", "oidc", started.State, authmodel.AuthProviderCallbackInput{}, assertionAdapter{assertion: assertion}); authProviderTestErrorCode(err) != "auth.external_account_unlinked" {
		t.Fatalf("unlinked callback error=%v", err)
	}
	if len(identityRepository.users) != 0 || len(authRepository.accounts) != 0 {
		t.Fatalf("users=%#v accounts=%#v", identityRepository.users, authRepository.accounts)
	}
}

func TestVerifiedOIDCCallbackLinksOnlyTheAuthenticatedChallengeUser(t *testing.T) {
	auth, identityRepository, authRepository := newFaultAuthDomainService()
	identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user-current", "current@example.test")}
	providers := NewAuthProviderDomainService([]map[string]any{{
		"key": "feishu", "type": "oidc", "enabled": true,
		"auth_url": "https://open.feishu.cn/open-apis/authen/v1/authorize", "client_id": "client", "redirect_url": "https://app.example/callback",
	}}, false)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	started, err := flows.StartExternalAccountLinkForApplication(t.Context(), "workspace-application", "user-current", "feishu", "aurora", "https://aurora.example/sso/callback")
	if err != nil {
		t.Fatal(err)
	}
	challenge := auth.challenges[started.State]
	if challenge.Purpose != authmodel.AuthChallengePurposeLink || challenge.UserID != "user-current" || challenge.ReturnURL != "https://aurora.example/sso/callback" {
		t.Fatalf("link challenge=%#v", challenge)
	}
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "feishu", Subject: "verified-feishu-user", Email: "current@example.test", ProviderSubjectVerified: true}
	session, completed, err := flows.ExchangeAndCompleteCallbackWithChallenge(t.Context(), "workspace-application", "feishu", started.State, authmodel.AuthProviderCallbackInput{}, assertionAdapter{assertion: assertion})
	if err != nil || session.User.UserID != "user-current" || completed.Purpose != authmodel.AuthChallengePurposeLink {
		t.Fatalf("session=%#v challenge=%#v err=%v", session, completed, err)
	}
	if len(authRepository.accounts) != 1 || authRepository.accounts[0].UserID != "user-current" || authRepository.accounts[0].ProviderSubject != "verified-feishu-user" {
		t.Fatalf("linked accounts=%#v", authRepository.accounts)
	}
	if _, _, err := flows.ExchangeAndCompleteCallbackWithChallenge(t.Context(), "workspace-application", "feishu", started.State, authmodel.AuthProviderCallbackInput{}, assertionAdapter{assertion: assertion}); authProviderTestErrorCode(err) != "auth.provider_state_invalid" {
		t.Fatalf("link callback replay error=%v", err)
	}
}

func TestExternalAccountLinkRejectsUnverifiedOrMismatchedProviderAssertions(t *testing.T) {
	for _, test := range []struct {
		name      string
		assertion authmodel.AuthExternalIdentityAssertion
		wantCode  string
	}{
		{name: "unverified", assertion: authmodel.AuthExternalIdentityAssertion{Provider: "feishu", Subject: "subject"}, wantCode: "auth.external_account_unverified"},
		{name: "provider mismatch", assertion: authmodel.AuthExternalIdentityAssertion{Provider: "other", Subject: "subject", ProviderSubjectVerified: true}, wantCode: "auth.external_account_provider_mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth, identityRepository, authRepository := newFaultAuthDomainService()
			identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user-current", "current@example.test")}
			providers := NewAuthProviderDomainService([]map[string]any{{"key": "feishu", "type": "oidc", "enabled": true, "auth_url": "https://open.feishu.cn/authorize", "client_id": "client", "redirect_url": "https://app.example/callback"}}, false)
			flows := NewAuthProviderFlowDomainService(auth, providers)
			started, err := flows.StartExternalAccountLinkForApplication(t.Context(), "workspace-application", "user-current", "feishu", "aurora", "https://aurora.example/sso/callback")
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = flows.ExchangeAndCompleteCallbackWithChallenge(t.Context(), "workspace-application", "feishu", started.State, authmodel.AuthProviderCallbackInput{}, assertionAdapter{assertion: test.assertion})
			if authProviderTestErrorCode(err) != test.wantCode || len(authRepository.accounts) != 0 {
				t.Fatalf("error=%v accounts=%#v", err, authRepository.accounts)
			}
		})
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
