package identityprovider

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

func TestExchangeFeishuCallbackSendsBoundPKCEVerifier(t *testing.T) {
	const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	digest := sha256.Sum256([]byte(codeVerifier))
	if got := base64.RawURLEncoding.EncodeToString(digest[:]); got != codeChallenge {
		t.Fatalf("code_challenge = %q, want %q", got, codeChallenge)
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Code         string `json:"code"`
			CodeVerifier string `json:"code_verifier"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		verifierDigest := sha256.Sum256([]byte(payload.CodeVerifier))
		if payload.Code != "code" || base64.RawURLEncoding.EncodeToString(verifierDigest[:]) != codeChallenge {
			http.Error(w, "PKCE verification failed", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"code":0,"access_token":"feishu-token"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer feishu-token" {
			t.Fatal("missing bearer token")
		}
		_, _ = w.Write([]byte(`{"code":0,"data":{"union_id":"union-1","name":"Feishu User"}}`))
	})
	config := authmodel.AuthProviderConfig{TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/userinfo"}
	assertion, err := ExchangeOIDCCallback(t.Context(), "feishu", "code", config, authmodel.AuthProviderChallenge{State: "state", CodeVerifier: codeVerifier})
	if err != nil {
		t.Fatal(err)
	}
	if assertion.Provider != "feishu" || assertion.Subject != "union-1" {
		t.Fatalf("assertion = %#v", assertion)
	}
	if _, err := ExchangeOIDCCallback(t.Context(), "feishu", "code", config, authmodel.AuthProviderChallenge{State: "state"}); err == nil {
		t.Fatal("missing PKCE verifier was accepted")
	}
	if _, err := ExchangeOIDCCallback(t.Context(), "feishu", "code", config, authmodel.AuthProviderChallenge{State: "state", CodeVerifier: "wrong-verifier"}); err == nil {
		t.Fatal("incorrect PKCE verifier was accepted")
	}
}
