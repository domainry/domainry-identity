package identityprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestExchangeWeChatMiniProgramCodeUsesUnionIDAndDiscardsSessionKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("appid") != "app-id" || r.URL.Query().Get("secret") != "app-secret" || r.URL.Query().Get("js_code") != "login-code" || r.URL.Query().Get("grant_type") != "authorization_code" {
			t.Fatalf("query=%s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"openid":"open-1","unionid":"union-1","session_key":"must-not-leak"}`))
	}))
	defer server.Close()
	assertion, err := ExchangeWeChatMiniProgramCode(t.Context(), "wechat_mini_program", " login-code ", authmodel.AuthProviderConfig{ClientID: "app-id", ClientSecret: "app-secret", TokenURL: server.URL})
	if err != nil || assertion.Subject != "union-1" || !assertion.ProviderSubjectVerified || assertion.Claims["openid"] != "open-1" || assertion.Claims["unionid"] != "union-1" {
		t.Fatalf("assertion=%#v err=%v", assertion, err)
	}
	if strings.Contains(assertion.Metadata, "session_key") || assertion.Claims["session_key"] != "" {
		t.Fatalf("session key leaked in assertion=%#v", assertion)
	}
}

func TestExchangeWeChatMiniProgramCodeRejectsProviderErrorsAndMissingIdentity(t *testing.T) {
	for name, response := range map[string]string{
		"provider error":   `{"errcode":40029,"errmsg":"invalid code"}`,
		"missing identity": `{"session_key":"secret"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(response)) }))
			defer server.Close()
			if _, err := ExchangeWeChatMiniProgramCode(t.Context(), "wechat_mini_program", "code", authmodel.AuthProviderConfig{ClientID: "app", ClientSecret: "secret", TokenURL: server.URL}); err == nil {
				t.Fatal("invalid provider response accepted")
			}
		})
	}
	if _, err := ExchangeWeChatMiniProgramCode(t.Context(), "wechat_mini_program", "", authmodel.AuthProviderConfig{}); err == nil {
		t.Fatal("missing code and credentials accepted")
	}
}

func TestCallbackAdapterCodeExchangeRejectsOtherProviderTypes(t *testing.T) {
	if _, err := (CallbackAdapter{}).ExchangeCode(t.Context(), "oidc", authmodel.AuthProviderConfig{Type: "oidc"}, "code"); err == nil {
		t.Fatal("OIDC provider accepted by direct code exchange")
	}
}

func TestCallbackAdapterUsesRegisteredCustomCodeExchange(t *testing.T) {
	called := false
	adapter := CallbackAdapter{CodeExchanges: map[string]func(context.Context, string, string, authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error){
		"partner": func(_ context.Context, provider, code string, _ authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error) {
			called = provider == "custom" && code == "code"
			return authmodel.AuthExternalIdentityAssertion{Provider: provider, Subject: "subject"}, nil
		},
	}}
	assertion, err := adapter.ExchangeCode(t.Context(), "custom", authmodel.AuthProviderConfig{Type: "code_exchange", Adapter: "partner"}, "code")
	if err != nil || !called || assertion.Subject != "subject" {
		t.Fatalf("called=%v assertion=%#v err=%v", called, assertion, err)
	}
}
