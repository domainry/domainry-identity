package identityprovider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestExchangeGitHubOAuthUsesPKCEAndStableNumericID(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") != "code" || r.FormValue("code_verifier") != "verifier" {
			t.Fatalf("token form=%v", r.Form)
		}
		_, _ = w.Write([]byte(`{"access_token":"token"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatal("missing bearer token")
		}
		_, _ = w.Write([]byte(`{"id":123,"login":"octocat","name":"Octo Cat","avatar_url":"avatar"}`))
	})
	assertion, err := ExchangeOAuth2Callback(t.Context(), "github", "code", authmodel.AuthProviderConfig{Adapter: "github", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/callback", TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/user"}, authmodel.AuthProviderChallenge{State: "state", CodeVerifier: "verifier"})
	if err != nil || assertion.Subject != "123" || assertion.DisplayName != "Octo Cat" {
		t.Fatalf("assertion=%#v err=%v", assertion, err)
	}
}

func TestExchangeDingTalkOAuthUsesUnionID(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			t.Fatal("token request is not JSON")
		}
		_, _ = w.Write([]byte(`{"accessToken":"token"}`))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-acs-dingtalk-access-token") != "token" {
			t.Fatal("missing DingTalk access token")
		}
		_, _ = w.Write([]byte(`{"unionId":"union-1","openId":"open-1","nick":"User"}`))
	})
	assertion, err := ExchangeOAuth2Callback(t.Context(), "dingtalk", "code", authmodel.AuthProviderConfig{Adapter: "dingtalk", ClientID: "client", ClientSecret: "secret", TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/me"}, authmodel.AuthProviderChallenge{State: "state"})
	if err != nil || assertion.Subject != "union-1" || assertion.DisplayName != "User" {
		t.Fatalf("assertion=%#v err=%v", assertion, err)
	}
}

func TestExchangeWeComOAuthUsesCorporateUserID(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("corpid") != "corp" || r.URL.Query().Get("corpsecret") != "secret" {
			t.Fatalf("token query=%s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"errcode":0,"access_token":"token"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("access_token") != "token" || r.URL.Query().Get("code") != "code" {
			t.Fatalf("user query=%s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"errcode":0,"UserId":"employee-1"}`))
	})
	assertion, err := ExchangeOAuth2Callback(t.Context(), "wecom", "code", authmodel.AuthProviderConfig{Adapter: "wecom", ClientID: "corp", ClientSecret: "secret", TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/user"}, authmodel.AuthProviderChallenge{State: "state"})
	if err != nil || assertion.Subject != "employee-1" {
		t.Fatalf("assertion=%#v err=%v", assertion, err)
	}
}

func TestExchangeInstagramOAuthCrossChecksTokenUserID(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("client_id") != "client" || r.FormValue("code") != "code" {
			t.Fatalf("token form=%v", r.Form)
		}
		_, _ = w.Write([]byte(`{"access_token":"token","user_id":"ig-1"}`))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("access_token") != "token" || r.URL.Query().Get("fields") == "" {
			t.Fatalf("userinfo query=%s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"id":"ig-1","username":"creator","account_type":"BUSINESS"}`))
	})
	assertion, err := ExchangeOAuth2Callback(t.Context(), "instagram", "code", authmodel.AuthProviderConfig{Adapter: "instagram", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/callback", TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/me"}, authmodel.AuthProviderChallenge{State: "state"})
	if err != nil || assertion.Subject != "ig-1" || assertion.DisplayName != "creator" || assertion.Claims["access_token"] != "" {
		t.Fatalf("assertion=%#v err=%v", assertion, err)
	}
}

func TestGenericOAuth2SupportsDiscordStableUserID(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"access_token":"token"}`)) })
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatal("missing Discord bearer token")
		}
		_, _ = w.Write([]byte(`{"id":"discord-1","username":"user","global_name":"Display","email":"user@example.com"}`))
	})
	assertion, err := ExchangeOAuth2Callback(t.Context(), "discord", "code", authmodel.AuthProviderConfig{Adapter: "generic_oauth2", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app/callback", TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/me"}, authmodel.AuthProviderChallenge{State: "state", CodeVerifier: "verifier"})
	if err != nil || assertion.Subject != "discord-1" || assertion.Email != "user@example.com" {
		t.Fatalf("assertion=%#v err=%v", assertion, err)
	}
}
