package identityprovider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestCallbackAdapterFormalAndCancellationEdges(t *testing.T) {
	want := authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject"}
	called := false
	adapter := CallbackAdapter{ExchangeOIDCCallback: func(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig, challenge authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, error) {
		called = true
		if ctx.Err() != nil || provider != "OIDC" || code != "code" || challenge.State != "state" {
			t.Fatalf("provider=%q code=%q challenge=%+v err=%v", provider, code, challenge, ctx.Err())
		}
		return want, nil
	}}
	assertion, err := adapter.Exchange(t.Context(), "OIDC", authmodel.AuthProviderConfig{Type: "oidc"}, authmodel.AuthProviderChallenge{State: "state"}, authmodel.AuthProviderCallbackInput{Values: map[string]string{"code": " code "}})
	if err != nil || !called || assertion.Subject != want.Subject {
		t.Fatalf("assertion=%+v called=%v err=%v", assertion, called, err)
	}

	verifyAssertion := authmodel.AuthExternalIdentityAssertion{Provider: "saml", Subject: "verified"}
	verify := func(string, string, map[string]any, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, bool) {
		return verifyAssertion, true
	}
	assertion, err = (CallbackAdapter{}).exchangeSAML(t.Context(), "saml", nil, authmodel.AuthProviderChallenge{}, map[string]string{}, verify)
	if err != nil || assertion.Subject != "verified" {
		t.Fatalf("formal SAML assertion=%+v err=%v", assertion, err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (CallbackAdapter{}).exchangeSAML(canceled, "saml", nil, authmodel.AuthProviderChallenge{}, nil, verify); !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("pre-verify cancel err=%v", err)
	}
	canceledAfter, cancelAfter := context.WithCancel(t.Context())
	if _, err := (CallbackAdapter{}).exchangeSAML(canceledAfter, "saml", nil, authmodel.AuthProviderChallenge{}, nil, func(string, string, map[string]any, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, bool) {
		cancelAfter()
		return verifyAssertion, true
	}); !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("post-verify cancel err=%v", err)
	}
	if _, err := (CallbackAdapter{}).exchangeSAML(t.Context(), "saml", nil, authmodel.AuthProviderChallenge{}, nil, func(string, string, map[string]any, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, bool) {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}); err == nil || err.Error() != "auth.provider_token_exchange_not_configured" {
		t.Fatalf("verify rejection err=%v", err)
	}
	customSAML := CallbackAdapter{VerifySAMLResponse: verify}
	assertion, err = customSAML.Exchange(t.Context(), "saml", authmodel.AuthProviderConfig{Type: "saml"}, authmodel.AuthProviderChallenge{}, authmodel.AuthProviderCallbackInput{})
	if err != nil || assertion.Subject != "verified" {
		t.Fatalf("custom verifier assertion=%+v err=%v", assertion, err)
	}
	if _, ok := mockOIDCAssertion("oidc", map[string]any{"issuer": "issuer", "client_id": "client"}, authmodel.AuthProviderChallenge{Nonce: "nonce"}, map[string]string{"mock_subject": "subject", "issuer": "wrong", "audience": "client", "nonce": "nonce"}); ok {
		t.Fatal("invalid mock OIDC claims accepted")
	}
	if _, ok := mockSAMLAssertion("saml", map[string]any{"client_id": "client", "redirect_url": "https://app/callback"}, authmodel.AuthProviderChallenge{}, map[string]string{"NameID": "subject"}); ok {
		t.Fatal("stateless mock SAML accepted")
	}
	if _, ok := mockSAMLAssertion("saml", map[string]any{"client_id": "client", "redirect_url": "https://app/callback"}, authmodel.AuthProviderChallenge{State: "state"}, map[string]string{"NameID": "subject", "audience": "wrong"}); ok {
		t.Fatal("invalid mock SAML claims accepted")
	}
}

func TestOIDCRequestConstructionAndFeishuProjectionEdges(t *testing.T) {
	if _, _, err := exchangeGenericToken(t.Context(), "code", authmodel.AuthProviderConfig{TokenURL: "http://bad\nheader"}); err == nil {
		t.Fatal("malformed token URL accepted")
	}
	if _, err := fetchGenericUserInfo(t.Context(), "token", "oidc", authmodel.AuthProviderConfig{UserInfoURL: "http://bad\nheader"}, nil); err == nil {
		t.Fatal("malformed userinfo URL accepted")
	}
	if _, err := exchangeFeishuToken(t.Context(), "code", authmodel.AuthProviderConfig{TokenURL: "http://bad\nheader"}); err == nil {
		t.Fatal("malformed Feishu token URL accepted")
	}
	if _, err := fetchFeishuUserInfo(t.Context(), "token", authmodel.AuthProviderConfig{UserInfoURL: "http://bad\nheader"}); err == nil {
		t.Fatal("malformed Feishu user URL accepted")
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/top-token", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"access_token":"top"}`)) })
	mux.HandleFunc("/nested-access", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"access_token":"nested"}}`))
	})
	mux.HandleFunc("/nested-user", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"union_id":"union","email":"user@example.com","name":"User","avatar_url":"avatar"}}`))
	})
	mux.HandleFunc("/invalid", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{`)) })
	for path, want := range map[string]string{"/top-token": "top", "/nested-access": "nested"} {
		token, err := exchangeFeishuToken(t.Context(), "code", authmodel.AuthProviderConfig{TokenURL: server.URL + path})
		if err != nil || token != want {
			t.Fatalf("path=%s token=%q err=%v", path, token, err)
		}
	}
	assertion, err := fetchFeishuUserInfo(t.Context(), "token", authmodel.AuthProviderConfig{UserInfoURL: server.URL + "/nested-user"})
	if err != nil || assertion.Subject != "union" || assertion.Email != "user@example.com" || assertion.DisplayName != "User" || assertion.AvatarURL != "avatar" {
		t.Fatalf("assertion=%+v err=%v", assertion, err)
	}
	if _, err := fetchFeishuUserInfo(t.Context(), "token", authmodel.AuthProviderConfig{UserInfoURL: server.URL + "/invalid"}); err == nil {
		t.Fatal("invalid Feishu userinfo accepted")
	}
	if _, err := exchangeFeishuToken(t.Context(), "code", authmodel.AuthProviderConfig{TokenURL: server.URL + "/invalid"}); err == nil {
		t.Fatal("invalid Feishu token response accepted")
	}
	if _, err := ExchangeOIDCCallback(t.Context(), "oidc", "code", authmodel.AuthProviderConfig{}, authmodel.AuthProviderChallenge{State: "state"}); err == nil {
		t.Fatal("generic exchange token failure accepted")
	}
	if _, err := ExchangeOIDCCallback(t.Context(), "feishu", "code", authmodel.AuthProviderConfig{TokenURL: "http://bad\nheader"}, authmodel.AuthProviderChallenge{State: "state"}); err == nil {
		t.Fatal("Feishu exchange token failure accepted")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := exchangeFeishuToken(canceled, "code", authmodel.AuthProviderConfig{}); err == nil {
		t.Fatal("default Feishu token endpoint ignored cancellation")
	}
	if _, err := fetchFeishuUserInfo(canceled, "token", authmodel.AuthProviderConfig{}); err == nil {
		t.Fatal("default Feishu user endpoint ignored cancellation")
	}
	assertion, err = ExchangeOIDCCallback(t.Context(), "LARK", "code", authmodel.AuthProviderConfig{TokenURL: server.URL + "/top-token", UserInfoURL: server.URL + "/nested-user"}, authmodel.AuthProviderChallenge{State: "state"})
	if err != nil || assertion.Provider != "lark" || assertion.Subject != "union" {
		t.Fatalf("Lark assertion=%+v err=%v", assertion, err)
	}
}

func TestSAMLSubjectExpiryFallbackAndMockAssertionEdges(t *testing.T) {
	now := time.Now().UTC()
	config := map[string]any{"client_id": "audience", "redirect_url": "https://app.example/callback", "client_secret": "secret"}
	challenge := authmodel.AuthProviderChallenge{State: "state"}
	notBefore := now.Add(-time.Minute).Format(time.RFC3339)
	notAfter := now.Add(time.Minute).Format(time.RFC3339)
	signature := expectedSAMLXMLSignature(config, "subject", "audience", "https://app.example/callback", "state", notBefore, notAfter)
	payload := `<Assertion><Subject><NameID>subject</NameID><SubjectConfirmation><SubjectConfirmationData InResponseTo="state" Recipient="https://app.example/callback" NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation></Subject><Conditions NotBefore="` + notBefore + `"><AudienceRestriction><Audience>audience</Audience></AudienceRestriction></Conditions><Signature><SignatureValue>` + signature + `</SignatureValue></Signature></Assertion>`
	if _, ok := VerifySAMLXMLResponse("saml", payload, config, challenge); ok {
		t.Fatal("custom SAML hash fallback accepted")
	}
	if samlProviderCertificates(map[string]any{}) != nil {
		t.Fatal("empty certificate material returned certificates")
	}
	if decoded, ok := decodeSAMLXMLPayload("PEFzc2VydGlvbi8+"); !ok || string(decoded) != "<Assertion/>" {
		t.Fatalf("raw base64 decoded=%q ok=%v", decoded, ok)
	}
	if samlXMLAssertionValid(config, challenge, payload, "subject", "wrong", "https://app.example/callback", "state", notBefore, notAfter, signature) {
		t.Fatal("invalid SAML audience accepted")
	}
	previousValidate := validateSAMLXMLSignature
	validateSAMLXMLSignature = func(*dsig.ValidationContext, *etree.Element) error { return nil }
	t.Cleanup(func() { validateSAMLXMLSignature = previousValidate })
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := server.Certificate()
	server.Close()
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	signedCandidate := `<Response><Signature/></Response>`
	if !samlXMLDSigVerified(signedCandidate, []*x509.Certificate{certificate}) {
		t.Fatal("injected valid DSig candidate rejected")
	}
	certificateConfig := map[string]any{"client_id": "audience", "redirect_url": "https://app.example/callback", "client_secret": string(certificatePEM)}
	if !samlXMLAssertionValid(certificateConfig, challenge, signedCandidate, "subject", "audience", "https://app.example/callback", "state", notBefore, notAfter, "ignored") {
		t.Fatal("certificate-backed SAML validation rejected")
	}
	if _, ok := mockOIDCAssertion("oidc", map[string]any{}, authmodel.AuthProviderChallenge{}, map[string]string{}); ok {
		t.Fatal("invalid mock OIDC accepted")
	}
	if _, ok := mockSAMLAssertion("saml", config, challenge, map[string]string{"SAMLResponse": payload}); ok {
		t.Fatal("mock SAML assertion accepted")
	}
}

func TestIdentityProviderConditionOutcomeMatrix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"userinfo","email":"userinfo@example.com"}`))
	}))
	defer server.Close()
	assertion, err := fetchGenericUserInfo(t.Context(), "token", "oidc", authmodel.AuthProviderConfig{UserInfoURL: server.URL}, map[string]string{"id": "token-id", "blank": " "})
	if err != nil || assertion.Subject != "userinfo" || assertion.Claims["blank"] != "" {
		t.Fatalf("assertion=%+v err=%v", assertion, err)
	}

	previousClient := callbackHTTPClient
	callbackHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusSwitchingProtocols, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	t.Cleanup(func() { callbackHTTPClient = previousClient })
	request, err := http.NewRequest(http.MethodGet, "https://provider.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeJSON(request, "provider"); err == nil || !strings.Contains(err.Error(), "status 101") {
		t.Fatalf("1xx err=%v", err)
	}

	claims := claimsFromMap(map[string]any{"": "ignored", "empty": " ", "email": "local"})
	if claims["email_domain"] != "" {
		t.Fatalf("email domain=%q", claims["email_domain"])
	}
	claims = claimsFromMap(map[string]any{"email": "local@"})
	if claims["email_domain"] != "" {
		t.Fatalf("trailing email domain=%q", claims["email_domain"])
	}
	statement := samlXMLAttributeStatement{Attributes: []samlXMLAttribute{
		{Values: []string{"value"}},
		{Name: "email", Values: []string{"local"}},
	}}
	projected := samlXMLAttributeClaims(statement)
	if projected["email_domain"] != "" {
		t.Fatalf("SAML email domain=%q", projected["email_domain"])
	}
	statement.Attributes[1].Values[0] = "local@"
	projected = samlXMLAttributeClaims(statement)
	if projected["email_domain"] != "" {
		t.Fatalf("SAML trailing email domain=%q", projected["email_domain"])
	}

	now := time.Now().UTC()
	validConfig := map[string]any{"issuer": "issuer", "client_id": "client"}
	if MockOIDCClaimsValid(map[string]any{"issuer": "issuer"}, authmodel.AuthProviderChallenge{Nonce: "nonce"}, "issuer", "", "nonce") || MockOIDCClaimsValid(validConfig, authmodel.AuthProviderChallenge{}, "issuer", "client", "") {
		t.Fatal("incomplete OIDC mock config accepted")
	}
	samlConfig := map[string]any{"client_id": "audience", "redirect_url": "https://app/callback"}
	challenge := authmodel.AuthProviderChallenge{State: "state"}
	base := []string{"subject", "audience", "https://app/callback", "state", now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339), "mock-signature:subject:audience"}
	if MockSAMLAssertionValid(map[string]any{"client_id": "audience"}, challenge, base[0], base[1], base[2], base[3], base[4], base[5], base[6]) {
		t.Fatal("missing SAML destination config accepted")
	}
	for index, mutate := range []func([]string){
		func(values []string) { values[2] = "wrong" },
		func(values []string) { values[3] = "wrong" },
		func(values []string) { values[4] = now.Add(10 * time.Minute).Format(time.RFC3339) },
		func(values []string) { values[5] = "invalid" },
	} {
		values := append([]string(nil), base...)
		mutate(values)
		if MockSAMLAssertionValid(samlConfig, challenge, values[0], values[1], values[2], values[3], values[4], values[5], values[6]) {
			t.Fatalf("invalid SAML condition %d accepted", index)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }
