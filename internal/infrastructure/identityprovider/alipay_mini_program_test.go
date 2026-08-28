package identityprovider

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestExchangeAlipayMiniProgramCodeVerifiesSignedIdentity(t *testing.T) {
	applicationKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	alipayKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"code":"10000","user_id":"user-1","open_id":"open-1","access_token":"transient-token"}`)
	digest := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, alipayKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("app_id") != "app-id" || r.Form.Get("code") != "auth-code" || r.Form.Get("method") != "alipay.system.oauth.token" || r.Form.Get("sign") == "" {
			t.Fatalf("form=%v err=%v", r.Form, err)
		}
		_, _ = w.Write([]byte(`{"alipay_system_oauth_token_response":` + string(payload) + `,"sign":"` + base64.StdEncoding.EncodeToString(signature) + `"}`))
	}))
	defer server.Close()
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, applicationKey)})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustMarshalPKIX(t, &alipayKey.PublicKey)})
	assertion, err := ExchangeAlipayMiniProgramCode(t.Context(), "alipay_mini_program", "auth-code", authmodel.AuthProviderConfig{ClientID: "app-id", ClientSecret: string(privatePEM), VerificationKey: string(publicPEM), TokenURL: server.URL})
	if err != nil || assertion.Subject != "user-1" || assertion.Claims["open_id"] != "open-1" || assertion.Claims["access_token"] != "" {
		t.Fatalf("assertion=%#v err=%v", assertion, err)
	}
}

func TestExchangeAlipayMiniProgramCodeRejectsUnsignedResponse(t *testing.T) {
	applicationKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	alipayKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"alipay_system_oauth_token_response":{"code":"10000","user_id":"user","access_token":"token"},"sign":"invalid"}`))
	}))
	defer server.Close()
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, applicationKey)})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustMarshalPKIX(t, &alipayKey.PublicKey)})
	if _, err := ExchangeAlipayMiniProgramCode(t.Context(), "alipay_mini_program", "code", authmodel.AuthProviderConfig{ClientID: "app", ClientSecret: string(privatePEM), VerificationKey: string(publicPEM), TokenURL: server.URL}); err == nil {
		t.Fatal("unsigned Alipay response accepted")
	}
}

func mustMarshalPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustMarshalPKIX(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
