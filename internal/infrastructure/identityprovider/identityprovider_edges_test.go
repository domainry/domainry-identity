package identityprovider

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func samlAssertionXML(t *testing.T, config map[string]any, challenge authmodel.AuthProviderChallenge, subject string) string {
	t.Helper()
	notBefore := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	notAfter := time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
	audience := stringFromProviderConfig(config, "client_id")
	destination := stringFromProviderConfig(config, "redirect_url")
	signature := expectedSAMLXMLSignature(config, subject, audience, destination, challenge.State, notBefore, notAfter)
	return `<Assertion><Subject><NameID>` + subject + `</NameID><SubjectConfirmation><SubjectConfirmationData InResponseTo="` + challenge.State + `" Recipient="` + destination + `" NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation></Subject><Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>` + audience + `</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute FriendlyName="email"><AttributeValue>USER@example.com</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><AttributeValue>User One</AttributeValue></Attribute><Attribute Name="ignored"><AttributeValue> </AttributeValue></Attribute><Attribute Name="empty"/></AttributeStatement><Signature><SignatureValue>` + signature + `</SignatureValue></Signature></Assertion>`
}

func TestVerifySAMLXMLResponseRawBase64AndResponseSignature(t *testing.T) {
	config := map[string]any{"client_id": "runtime", "redirect_url": "https://app.example/callback", "client_secret": "secret"}
	challenge := authmodel.AuthProviderChallenge{State: "request-1"}
	assertionXML := samlAssertionXML(t, config, challenge, "user-1")
	for _, payload := range []string{assertionXML, base64.StdEncoding.EncodeToString([]byte(assertionXML)), base64.RawStdEncoding.EncodeToString([]byte(assertionXML))} {
		if _, ok := VerifySAMLXMLResponse("SAML", payload, config, challenge); ok {
			t.Fatal("non-certificate SAML assertion accepted")
		}
	}

	withoutSignature := strings.Replace(assertionXML, `<Signature><SignatureValue>`+expectedSAMLXMLSignature(config, "user-1", "runtime", "https://app.example/callback", challenge.State,
		strings.TrimSpace(mustSAMLField(t, assertionXML, "NotBefore")), strings.TrimSpace(mustSAMLField(t, assertionXML, "NotOnOrAfter")))+`</SignatureValue></Signature>`, "", 1)
	responseSignature := expectedSAMLXMLSignature(config, "user-1", "runtime", "https://app.example/callback", challenge.State, mustSAMLField(t, assertionXML, "NotBefore"), mustSAMLField(t, assertionXML, "NotOnOrAfter"))
	responseXML := `<Response><Signature><SignatureValue>` + responseSignature + `</SignatureValue></Signature>` + withoutSignature + `</Response>`
	if _, ok := VerifySAMLXMLResponse("saml", responseXML, config, challenge); ok {
		t.Fatal("custom response signature accepted")
	}
}

func mustSAMLField(t *testing.T, payload, field string) string {
	t.Helper()
	assertion, _, ok := parseSAMLXMLAssertion(payload)
	if !ok {
		t.Fatal("parse assertion")
	}
	if field == "NotBefore" {
		return assertion.Conditions.NotBefore
	}
	return assertion.Conditions.NotOnOrAfter
}

func TestSAMLParsingValidationAndCertificateEdges(t *testing.T) {
	config := map[string]any{"client_id": "runtime", "redirect_url": "https://app.example/callback", "client_secret": "secret"}
	challenge := authmodel.AuthProviderChallenge{State: "request-1"}
	valid := samlAssertionXML(t, config, challenge, "user-1")
	invalidPayloads := []string{"", strings.Repeat("x", (1<<20)+1), "%%%", "<", `<Response/>`, `<Other/>`, strings.Replace(valid, "user-1", "", 1), strings.Replace(valid, "saml-sha256:", "bad:", 1)}
	for _, payload := range invalidPayloads {
		if _, ok := VerifySAMLXMLResponse("saml", payload, config, challenge); ok {
			t.Fatalf("invalid SAML accepted: %.80q", payload)
		}
	}
	if _, _, ok := parseSAMLXMLAssertion(`<Assertion>`); ok {
		t.Fatal("malformed assertion accepted")
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := server.Certificate()
	server.Close()
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("ignored")})
	certificates := samlProviderCertificates(map[string]any{"client_secret": string(keyPEM) + string(certificatePEM) + "bad"})
	if len(certificates) != 1 || !certificates[0].Equal(certificate) {
		t.Fatalf("certificates=%v", certificates)
	}
	if got := samlProviderCertificates(map[string]any{"client_secret": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")}))}); len(got) != 0 {
		t.Fatalf("invalid certificates=%v", got)
	}
	if samlXMLDSigVerified(valid, certificates) || samlXMLDSigVerified("%%%", certificates) || samlXMLDSigVerified("<", certificates) || samlXMLDSigVerified("<?xml version=\"1.0\"?>", certificates) {
		t.Fatal("unsigned or malformed XML passed DSig verification")
	}
}

func TestSAMLXMLHelpersAndMockValidationMatrix(t *testing.T) {
	if payload, ok := decodeSAMLXMLPayload(" <Assertion/> "); !ok || string(payload) != "<Assertion/>" {
		t.Fatalf("raw payload=%q ok=%v", payload, ok)
	}
	for _, payload := range []string{"", strings.Repeat("x", (1<<20)+1), "%%%", base64.StdEncoding.EncodeToString(make([]byte, (1<<20)+1))} {
		if _, ok := decodeSAMLXMLPayload(payload); ok {
			t.Fatalf("invalid payload decoded: len=%d", len(payload))
		}
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromString(`<samlp:Response><saml:Assertion><ds:Signature/></saml:Assertion><Other><Assertion/></Other><Signature/></samlp:Response>`); err != nil {
		t.Fatal(err)
	}
	candidates := samlXMLSignatureCandidates(doc.Root())
	if len(candidates) != 2 || samlXMLSignatureCandidates(nil) != nil || !samlXMLHasSignature(doc.Root()) || samlXMLHasSignature(doc.Root().FindElement("Other")) {
		t.Fatalf("candidates=%d", len(candidates))
	}
	if samlXMLLocalName("saml:Assertion") != "Assertion" || samlXMLLocalName("Assertion") != "Assertion" || samlXMLLocalName("prefix:") != "prefix:" {
		t.Fatal("local name normalization failed")
	}
	if expectedSAMLXMLSignature(map[string]any{}, "s", "a", "d", "r", "b", "e") != "" {
		t.Fatal("empty signing material produced signature")
	}

	now := time.Now().UTC()
	validConfig := map[string]any{"client_id": "runtime", "redirect_url": "https://app.example/callback"}
	challenge := authmodel.AuthProviderChallenge{State: "request-1"}
	validArgs := []string{"user-1", "runtime", "https://app.example/callback", "request-1", now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339), "mock-signature:user-1:runtime"}
	if !MockSAMLAssertionValid(validConfig, challenge, validArgs[0], validArgs[1], validArgs[2], validArgs[3], validArgs[4], validArgs[5], validArgs[6]) {
		t.Fatal("valid mock SAML rejected")
	}
	invalid := []struct {
		config    map[string]any
		challenge authmodel.AuthProviderChallenge
		args      []string
	}{
		{config: map[string]any{}, challenge: challenge, args: validArgs},
		{config: validConfig, challenge: authmodel.AuthProviderChallenge{}, args: validArgs},
		{config: validConfig, challenge: challenge, args: append([]string(nil), validArgs...)},
		{config: validConfig, challenge: challenge, args: append([]string(nil), validArgs...)},
		{config: validConfig, challenge: challenge, args: append([]string(nil), validArgs...)},
		{config: validConfig, challenge: challenge, args: append([]string(nil), validArgs...)},
	}
	invalid[2].args[1] = "wrong"
	invalid[3].args[6] = "wrong"
	invalid[4].args[4] = "invalid"
	invalid[5].args[5] = now.Add(-10 * time.Minute).Format(time.RFC3339)
	for index, test := range invalid {
		if MockSAMLAssertionValid(test.config, test.challenge, test.args[0], test.args[1], test.args[2], test.args[3], test.args[4], test.args[5], test.args[6]) {
			t.Fatalf("invalid mock SAML %d accepted", index)
		}
	}
	if _, ok := parseSAMLMockTime("invalid"); ok {
		t.Fatal("invalid SAML time accepted")
	}
	if parsed, ok := parseSAMLMockTime(" " + now.Format(time.RFC3339) + " "); !ok || parsed.Location() != time.UTC {
		t.Fatalf("parsed=%v ok=%v", parsed, ok)
	}
	if MockOIDCClaimsValid(map[string]any{}, authmodel.AuthProviderChallenge{}, "", "", "") || !MockOIDCClaimsValid(map[string]any{"issuer": "iss", "client_id": "client"}, authmodel.AuthProviderChallenge{Nonce: "nonce"}, "iss", "client", "nonce") {
		t.Fatal("OIDC mock validation matrix failed")
	}
	if stringFromAny((*x509.Certificate)(nil)) != "" || stringFromAny(" value ") != "value" {
		t.Fatal("generic string normalization failed")
	}
}

func TestOIDCAndFeishuFailureAndFallbackMatrix(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusBadGateway) })
	mux.HandleFunc("/invalid", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{`)) })
	mux.HandleFunc("/token-error", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"error_description":"denied"}`)) })
	mux.HandleFunc("/token-missing", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	mux.HandleFunc("/token-claims", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":"token-value","sub":"token-sub","email":"token@example.com"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"user-1","name":"User One"}`))
	})
	mux.HandleFunc("/feishu-error", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"code":9}`)) })
	mux.HandleFunc("/feishu-token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{"user_access_token":"nested-token"}}`))
	})
	mux.HandleFunc("/feishu-missing", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"code":0,"data":{}}`)) })
	mux.HandleFunc("/feishu-user", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"open_id":"open-1","enterprise_email":"user@example.com","en_name":"User","avatar_thumb":"avatar"}`))
	})

	challenge := authmodel.AuthProviderChallenge{State: "state"}
	if _, err := ExchangeOIDCCallback(t.Context(), "oidc", "", authmodel.AuthProviderConfig{}, challenge); err == nil {
		t.Fatal("empty callback code accepted")
	}
	if _, err := ExchangeOIDCCallback(t.Context(), "oidc", "code", authmodel.AuthProviderConfig{}, authmodel.AuthProviderChallenge{}); err == nil {
		t.Fatal("empty callback state accepted")
	}
	if _, _, err := exchangeGenericToken(t.Context(), "code", authmodel.AuthProviderConfig{}); err == nil {
		t.Fatal("missing token URL accepted")
	}
	for _, endpoint := range []string{"/status", "/invalid", "/token-error", "/token-missing"} {
		if _, _, err := exchangeGenericToken(t.Context(), "code", authmodel.AuthProviderConfig{TokenURL: server.URL + endpoint}); err == nil {
			t.Fatalf("generic token endpoint %s succeeded", endpoint)
		}
	}
	token, claims, err := exchangeGenericToken(t.Context(), " code ", authmodel.AuthProviderConfig{TokenURL: server.URL + "/token-claims"})
	if err != nil || token != "token-value" || claims["sub"] != "token-sub" {
		t.Fatalf("token=%q claims=%v err=%v", token, claims, err)
	}
	if _, err := fetchGenericUserInfo(t.Context(), token, "OIDC", authmodel.AuthProviderConfig{}, claims); err == nil {
		t.Fatal("missing userinfo URL accepted")
	}
	assertion, err := fetchGenericUserInfo(t.Context(), token, " OIDC ", authmodel.AuthProviderConfig{UserInfoURL: server.URL + "/userinfo", Issuer: "issuer"}, claims)
	if err != nil || assertion.Provider != "oidc" || assertion.Subject != "token-sub" || assertion.Email != "token@example.com" || assertion.Claims["issuer"] != "issuer" {
		t.Fatalf("assertion=%+v err=%v", assertion, err)
	}
	if _, err := fetchGenericUserInfo(t.Context(), token, "oidc", authmodel.AuthProviderConfig{UserInfoURL: server.URL + "/status"}, nil); err == nil {
		t.Fatal("userinfo status failure accepted")
	}

	for _, endpoint := range []string{"/feishu-error", "/feishu-missing"} {
		if _, err := exchangeFeishuToken(t.Context(), "code", authmodel.AuthProviderConfig{TokenURL: server.URL + endpoint}); err == nil {
			t.Fatalf("Feishu token endpoint %s succeeded", endpoint)
		}
	}
	feishuToken, err := exchangeFeishuToken(t.Context(), "code", authmodel.AuthProviderConfig{TokenURL: server.URL + "/feishu-token"})
	if err != nil || feishuToken != "nested-token" {
		t.Fatalf("Feishu token=%q err=%v", feishuToken, err)
	}
	if _, err := fetchFeishuUserInfo(t.Context(), feishuToken, authmodel.AuthProviderConfig{UserInfoURL: server.URL + "/feishu-error"}); err == nil {
		t.Fatal("Feishu user error accepted")
	}
	feishu, err := fetchFeishuUserInfo(t.Context(), feishuToken, authmodel.AuthProviderConfig{UserInfoURL: server.URL + "/feishu-user"})
	if err != nil || feishu.Subject != "open-1" || feishu.Email != "user@example.com" || feishu.DisplayName != "User" || feishu.AvatarURL != "avatar" {
		t.Fatalf("Feishu assertion=%+v err=%v", feishu, err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeJSON(request, "cancelled"); !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("execute cancellation error=%v", err)
	}
}
