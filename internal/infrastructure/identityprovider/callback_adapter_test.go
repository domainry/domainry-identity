package identityprovider

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import "testing"

func TestCallbackAdapterRejectsMockOIDC(t *testing.T) {
	config := authmodel.AuthProviderConfig{Type: "oidc", Issuer: "issuer", ClientID: "client"}
	challenge := authmodel.AuthProviderChallenge{State: "state", Nonce: "nonce"}
	for _, input := range []authmodel.AuthProviderCallbackInput{
		{Values: map[string]string{"code": "mock:user", "issuer": "issuer", "audience": "client", "nonce": "nonce"}},
		{Values: map[string]string{"mock_subject": "user", "issuer": "issuer", "audience": "client", "nonce": "nonce"}},
	} {
		if _, err := (CallbackAdapter{}).Exchange(t.Context(), "oidc", config, challenge, input); err == nil {
			t.Fatal("mock OIDC callback accepted")
		}
	}
}

func TestCallbackAdapterRejectsMockSAML(t *testing.T) {
	challenge := authmodel.AuthProviderChallenge{State: "state"}
	values := map[string]string{
		"SAMLResponse": "mock:user", "audience": "client", "destination": "https://app/callback",
		"in_response_to": "state", "signature": "mock-signature:user:client",
	}
	config := authmodel.AuthProviderConfig{Type: "saml", ClientID: "client", RedirectURL: "https://app/callback", ClientSecret: "mock-signature"}
	if _, err := (CallbackAdapter{}).Exchange(t.Context(), "saml", config, challenge, authmodel.AuthProviderCallbackInput{Values: values}); err == nil {
		t.Fatal("mock SAML callback accepted")
	}
}
