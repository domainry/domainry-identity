package service

import (
	"encoding/base64"
	"net/url"
	"strings"
)

func buildProviderAuthURL(authURL string, clientID string, redirectURL string, scope string, state string, nonce string, codeChallenge ...string) string {
	authURL = strings.TrimSpace(authURL)
	if authURL == "" {
		return ""
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		return ""
	}
	query := parsed.Query()
	query.Set("response_type", "code")
	query.Set("client_id", strings.TrimSpace(clientID))
	query.Set("redirect_uri", strings.TrimSpace(redirectURL))
	query.Set("state", strings.TrimSpace(state))
	if strings.TrimSpace(scope) != "" {
		query.Set("scope", strings.TrimSpace(scope))
	}
	if strings.TrimSpace(nonce) != "" {
		query.Set("nonce", strings.TrimSpace(nonce))
	}
	if len(codeChallenge) > 0 && strings.TrimSpace(codeChallenge[0]) != "" {
		query.Set("code_challenge", strings.TrimSpace(codeChallenge[0]))
		query.Set("code_challenge_method", "S256")
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func buildSAMLProviderAuthURL(ssoURL string, entityID string, acsURL string, relayState string, requestID ...string) string {
	ssoURL = strings.TrimSpace(ssoURL)
	if ssoURL == "" {
		return ""
	}
	parsed, err := url.Parse(ssoURL)
	if err != nil {
		return ""
	}
	query := parsed.Query()
	query.Set("RelayState", strings.TrimSpace(relayState))
	id := "_" + strings.TrimSpace(relayState)
	if len(requestID) > 0 && strings.TrimSpace(requestID[0]) != "" {
		id = strings.TrimSpace(requestID[0])
	}
	request := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="` + id + `" Version="2.0" AssertionConsumerServiceURL="` + strings.TrimSpace(acsURL) + `"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` + strings.TrimSpace(entityID) + `</saml:Issuer></samlp:AuthnRequest>`
	query.Set("SAMLRequest", base64.StdEncoding.EncodeToString([]byte(request)))
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func normalizeProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}
