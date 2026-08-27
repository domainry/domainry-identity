package identityprovider

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExchangeOIDCCallbackRejectsUnverifiedOAuthUserInfoFlow(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if got := r.FormValue("code"); got != "callback-code" {
			t.Fatalf("code = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token-value"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token-value" {
			t.Fatalf("authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"subject-1","email":"USER@example.com","name":"User One"}`))
	})
	if _, err := ExchangeOIDCCallback(t.Context(), "oidc", "callback-code", authmodel.AuthProviderConfig{TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/userinfo", ClientID: "client", ClientSecret: "secret"}, authmodel.AuthProviderChallenge{State: "state"}); err == nil {
		t.Fatal("OAuth-only userinfo flow was accepted as OIDC")
	}
}

func TestExchangeFeishuCallbackUsesProviderDefaultsOverride(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"access_token":"feishu-token"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer feishu-token" {
			t.Fatal("missing bearer token")
		}
		_, _ = w.Write([]byte(`{"code":0,"data":{"union_id":"union-1","name":"Feishu User"}}`))
	})
	assertion, err := ExchangeOIDCCallback(t.Context(), "feishu", "code", authmodel.AuthProviderConfig{TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/userinfo"}, authmodel.AuthProviderChallenge{State: "state"})
	if err != nil {
		t.Fatal(err)
	}
	if assertion.Provider != "feishu" || assertion.Subject != "union-1" {
		t.Fatalf("assertion = %#v", assertion)
	}
}
