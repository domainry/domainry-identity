package identityprovider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestExchangeLineLIFFIDTokenUsesOnlyVerifiedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatalf("request method=%s content-type=%s", r.Method, r.Header.Get("Content-Type"))
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("id_token") != "signed-token" || r.Form.Get("client_id") != "channel-id" {
			t.Fatalf("form=%v err=%v", r.Form, err)
		}
		_, _ = w.Write([]byte(`{"sub":"line-user","aud":"channel-id","name":"Verified Name","picture":"https://line.example/avatar","email":"verified@example.test"}`))
	}))
	defer server.Close()
	assertion, err := ExchangeLineLIFFIDToken(t.Context(), "line", " signed-token ", authmodel.AuthProviderConfig{ClientID: "channel-id", TokenURL: server.URL})
	if err != nil || assertion.Subject != "line-user" || assertion.Email != "verified@example.test" || assertion.DisplayName != "Verified Name" || !assertion.ProviderSubjectVerified {
		t.Fatalf("assertion=%+v err=%v", assertion, err)
	}
	if !strings.Contains(assertion.Metadata, "line_liff_id_token_verify") {
		t.Fatalf("metadata=%q", assertion.Metadata)
	}
}

func TestExchangeLineLIFFIDTokenRejectsInvalidClaims(t *testing.T) {
	for name, response := range map[string]string{
		"provider error":  `{"error":"invalid_request"}`,
		"wrong audience":  `{"sub":"line-user","aud":"other-channel"}`,
		"missing subject": `{"aud":"channel-id"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(response)) }))
			defer server.Close()
			if _, err := ExchangeLineLIFFIDToken(t.Context(), "line", "token", authmodel.AuthProviderConfig{ClientID: "channel-id", TokenURL: server.URL}); err == nil {
				t.Fatal("invalid LINE response accepted")
			}
		})
	}
}
