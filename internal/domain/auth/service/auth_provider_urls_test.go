package service

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestOIDCProviderAuthorizationURL(t *testing.T) {
	if buildProviderAuthURL(" ", "client", "callback", "scope", "state", "nonce") != "" {
		t.Fatal("blank provider URL must remain blank")
	}
	if buildProviderAuthURL("%", "client", "callback", "scope", "state", "nonce") != "" {
		t.Fatal("invalid provider URL must remain blank")
	}

	withoutOptional := parseProviderURL(t, buildProviderAuthURL("https://identity.example/authorize", " client ", " callback ", " ", " state ", " "))
	if withoutOptional.Get("client_id") != "client" || withoutOptional.Get("scope") != "" || withoutOptional.Get("nonce") != "" {
		t.Fatalf("unexpected base provider query: %v", withoutOptional)
	}
	withOptional := parseProviderURL(t, buildProviderAuthURL("https://identity.example/authorize?existing=value", "client", "callback", "openid profile", "state", "nonce"))
	if withOptional.Get("scope") != "openid profile" || withOptional.Get("nonce") != "nonce" || withOptional.Get("existing") != "value" {
		t.Fatalf("unexpected optional provider query: %v", withOptional)
	}
}

func TestSAMLProviderAuthorizationURL(t *testing.T) {
	if buildSAMLProviderAuthURL(" ", "entity", "callback", "state") != "" {
		t.Fatal("blank SAML URL must remain blank")
	}
	if buildSAMLProviderAuthURL("%", "entity", "callback", "state") != "" {
		t.Fatal("invalid SAML URL must remain blank")
	}
	query := parseProviderURL(t, buildSAMLProviderAuthURL("https://identity.example/sso", " entity ", " callback ", " relay "))
	if query.Get("RelayState") != "relay" {
		t.Fatalf("unexpected relay state: %v", query)
	}
	request, err := base64.StdEncoding.DecodeString(query.Get("SAMLRequest"))
	if err != nil || !strings.Contains(string(request), `AssertionConsumerServiceURL="callback"`) || !strings.Contains(string(request), `>entity</saml:Issuer>`) {
		t.Fatalf("unexpected SAML request %q: %v", request, err)
	}
}

func parseProviderURL(t *testing.T, value string) url.Values {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse provider URL %q: %v", value, err)
	}
	return parsed.Query()
}
