package identityprovider

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"strings"
)

func mockOIDCAssertion(provider string, config map[string]any, challenge authmodel.AuthProviderChallenge, values map[string]string) (authmodel.AuthExternalIdentityAssertion, bool) {
	code, subject := values["code"], values["mock_subject"]
	if strings.HasPrefix(code, "mock:") {
		subject = strings.TrimSpace(strings.TrimPrefix(code, "mock:"))
	}
	if subject == "" || !MockOIDCClaimsValid(config, challenge, values["issuer"], values["audience"], values["nonce"]) {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	return authmodel.AuthExternalIdentityAssertion{Provider: provider, Subject: subject, Email: values["email"], DisplayName: values["display_name"], Claims: map[string]string{"email": values["email"], "display_name": values["display_name"], "issuer": values["issuer"], "audience": values["audience"]}, Metadata: `{"source":"mock_callback"}`}, true
}

func mockSAMLAssertion(provider string, config map[string]any, challenge authmodel.AuthProviderChallenge, values map[string]string) (authmodel.AuthExternalIdentityAssertion, bool) {
	response, subject := values["SAMLResponse"], values["NameID"]
	if strings.HasPrefix(response, "mock:") {
		subject = strings.TrimSpace(strings.TrimPrefix(response, "mock:"))
	} else if assertion, ok := VerifySAMLXMLResponse(provider, response, config, challenge); ok {
		return assertion, true
	}
	if subject == "" || strings.TrimSpace(challenge.State) == "" || !MockSAMLAssertionValid(config, challenge, subject, values["audience"], values["destination"], values["in_response_to"], values["not_before"], values["not_on_or_after"], values["signature"]) {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	return authmodel.AuthExternalIdentityAssertion{Provider: provider, Subject: subject, Email: values["email"], DisplayName: values["display_name"], Claims: map[string]string{"email": values["email"], "display_name": values["display_name"], "name_id": subject, "audience": values["audience"], "destination": values["destination"], "in_response_to": values["in_response_to"]}, Metadata: `{"source":"mock_saml_callback"}`}, true
}
