package auth

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/identityprovider"
)

func TestAuthProviderCallbackAdapterRejectsUnsignedSAMLXML(t *testing.T) {
	subject := "saml-user-1"
	audience := "saml-client"
	destination := "https://app.example.com/auth/callback/saml"
	state := "request-state"
	notBefore := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	notOnOrAfter := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	material := "saml-signing-material"
	digest := sha256.Sum256([]byte(strings.Join([]string{subject, audience, destination, state, notBefore, notOnOrAfter, material}, "|")))
	signature := "saml-sha256:" + hex.EncodeToString(digest[:])
	xml := `<Response><Assertion><Subject><NameID>` + subject + `</NameID><SubjectConfirmation><SubjectConfirmationData Recipient="` + destination + `" InResponseTo="` + state + `" NotOnOrAfter="` + notOnOrAfter + `"/></SubjectConfirmation></Subject><Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notOnOrAfter + `"><AudienceRestriction><Audience>` + audience + `</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="email"><AttributeValue>user@example.com</AttributeValue></Attribute></AttributeStatement><Signature><SignatureValue>` + signature + `</SignatureValue></Signature></Assertion></Response>`
	_, err := (identityprovider.CallbackAdapter{}).Exchange(t.Context(), "saml", authmodel.AuthProviderConfig{Type: "saml", ClientID: audience, ClientSecret: material, RedirectURL: destination}, authmodel.AuthProviderChallenge{State: state}, authmodel.AuthProviderCallbackInput{Method: "POST", Values: map[string]string{"SAMLResponse": base64.StdEncoding.EncodeToString([]byte(xml))}})
	if err == nil {
		t.Fatal("unsigned SAML assertion was accepted")
	}
}

func TestAuthProviderCallbackAdapterPropagatesCancelledSAMLContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := (identityprovider.CallbackAdapter{}).Exchange(ctx, "saml", authmodel.AuthProviderConfig{Type: "saml"}, authmodel.AuthProviderChallenge{}, authmodel.AuthProviderCallbackInput{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestAuthProviderCallbackAdapterSAMLVerificationOutcomes(t *testing.T) {
	adapter := identityprovider.CallbackAdapter{}
	adapter.VerifySAMLResponse = func(string, string, map[string]any, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, bool) {
		return authmodel.AuthExternalIdentityAssertion{Subject: "verified"}, true
	}
	assertion, err := adapter.Exchange(t.Context(), "saml", authmodel.AuthProviderConfig{Type: "saml"}, authmodel.AuthProviderChallenge{}, authmodel.AuthProviderCallbackInput{})
	if err != nil || assertion.Subject != "verified" {
		t.Fatalf("assertion=%#v err=%v", assertion, err)
	}
	adapter.VerifySAMLResponse = func(string, string, map[string]any, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, bool) {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	if _, err := adapter.Exchange(t.Context(), "saml", authmodel.AuthProviderConfig{Type: "saml"}, authmodel.AuthProviderChallenge{}, authmodel.AuthProviderCallbackInput{}); err == nil {
		t.Fatal("expected unavailable exchange error")
	}
	ctx, cancel := context.WithCancel(t.Context())
	adapter.VerifySAMLResponse = func(string, string, map[string]any, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, bool) {
		cancel()
		return authmodel.AuthExternalIdentityAssertion{Subject: "verified"}, true
	}
	if _, err := adapter.Exchange(ctx, "saml", authmodel.AuthProviderConfig{Type: "saml"}, authmodel.AuthProviderChallenge{}, authmodel.AuthProviderCallbackInput{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestAuthProviderCallbackAdapterOIDCOutcomes(t *testing.T) {
	adapter := identityprovider.CallbackAdapter{}
	config := authmodel.AuthProviderConfig{Type: "oidc", Issuer: "issuer", ClientID: "client"}
	challenge := authmodel.AuthProviderChallenge{State: "state", Nonce: "nonce"}
	if _, err := adapter.Exchange(t.Context(), "oidc", config, challenge, authmodel.AuthProviderCallbackInput{Method: "GET", Values: map[string]string{"code": "mock:user-1", "issuer": "issuer", "audience": "client", "nonce": "nonce"}}); err == nil {
		t.Fatal("mock OIDC callback was accepted by the production adapter")
	}
	adapter.ExchangeOIDCCallback = func(context.Context, string, string, authmodel.AuthProviderConfig, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, error) {
		return authmodel.AuthExternalIdentityAssertion{}, errors.New("exchange")
	}
	if _, err := adapter.Exchange(t.Context(), "oidc", config, challenge, authmodel.AuthProviderCallbackInput{}); err == nil {
		t.Fatal("expected exchange error")
	}
	adapter.ExchangeOIDCCallback = func(context.Context, string, string, authmodel.AuthProviderConfig, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, error) {
		return authmodel.AuthExternalIdentityAssertion{Subject: "live"}, nil
	}
	assertion, err := adapter.Exchange(t.Context(), "oidc", config, challenge, authmodel.AuthProviderCallbackInput{})
	if err != nil || assertion.Subject != "live" {
		t.Fatalf("assertion=%#v err=%v", assertion, err)
	}
}
