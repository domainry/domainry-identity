package identityprovider

import (
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

const samlBearerConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

// VerifyStrictSAMLResponse accepts only certificate-backed, signed SAML 2.0
// assertions. The parser supplies XML signature/wrapping, audience,
// destination and clock-window validation; the remaining correlation checks
// are explicit below.
func VerifyStrictSAMLResponse(provider, encodedResponse string, config map[string]any, challenge authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, bool) {
	encodedResponse = strings.TrimSpace(encodedResponse)
	if encodedResponse == "" || len(encodedResponse) > 12<<20 || strings.TrimSpace(challenge.State) == "" || strings.TrimSpace(challenge.RequestID) == "" {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	response, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil || len(response) > 8<<20 {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	certificates := samlProviderCertificates(config)
	issuer := strings.TrimSpace(stringFromProviderConfig(config, "issuer"))
	entityID := strings.TrimSpace(stringFromProviderConfig(config, "client_id"))
	ssoURL := strings.TrimSpace(stringFromProviderConfig(config, "auth_url"))
	acsRaw := strings.TrimSpace(stringFromProviderConfig(config, "redirect_url"))
	acsURL, acsErr := url.Parse(acsRaw)
	if len(certificates) == 0 || issuer == "" || entityID == "" || acsErr != nil || acsURL.Scheme != "https" || acsURL.Host == "" {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	keyDescriptors := make([]saml.KeyDescriptor, 0, len(certificates))
	for _, certificate := range certificates {
		keyDescriptors = append(keyDescriptors, samlSigningKeyDescriptor(certificate))
	}
	serviceProvider := &saml.ServiceProvider{
		EntityID: entityID, AcsURL: *acsURL, AllowIDPInitiated: false,
		IDPMetadata: &saml.EntityDescriptor{EntityID: issuer, IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor:        saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol", KeyDescriptors: keyDescriptors}},
			SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: ssoURL}},
		}}},
	}
	assertion, err := serviceProvider.ParseXMLResponse(response, []string{challenge.RequestID}, serviceProvider.AcsURL)
	if err != nil || assertion == nil || assertion.Signature == nil || assertion.Subject == nil || assertion.Subject.NameID == nil || assertion.Conditions == nil || strings.TrimSpace(assertion.ID) == "" || assertion.Issuer.Value != issuer {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	confirmation := strictBearerConfirmation(assertion, acsRaw, challenge.RequestID)
	if confirmation == nil {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	audienceOK := false
	for _, restriction := range assertion.Conditions.AudienceRestrictions {
		if restriction.Audience.Value == entityID {
			audienceOK = true
			break
		}
	}
	if !audienceOK {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	expiresAt := assertion.Conditions.NotOnOrAfter
	if !confirmation.NotOnOrAfter.IsZero() && (expiresAt.IsZero() || confirmation.NotOnOrAfter.Before(expiresAt)) {
		expiresAt = confirmation.NotOnOrAfter
	}
	if expiresAt.IsZero() || !expiresAt.After(time.Now().UTC()) {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	claims := map[string]string{"assertion_id": assertion.ID, "issuer": assertion.Issuer.Value, "name_id": strings.TrimSpace(assertion.Subject.NameID.Value), "audience": entityID, "destination": acsRaw, "in_response_to": challenge.RequestID, "not_on_or_after": expiresAt.UTC().Format(time.RFC3339Nano)}
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			key := strings.ToLower(strings.TrimSpace(attribute.Name))
			if key == "" {
				key = strings.ToLower(strings.TrimSpace(attribute.FriendlyName))
			}
			if key != "" && len(attribute.Values) > 0 && strings.TrimSpace(attribute.Values[0].Value) != "" {
				claims[key] = strings.TrimSpace(attribute.Values[0].Value)
			}
		}
	}
	return authmodel.AuthExternalIdentityAssertion{
		Provider: strings.ToLower(strings.TrimSpace(provider)), Subject: claims["name_id"],
		Email:       FirstNonEmptyClaim(claims, "email", "mail", "emailaddress"),
		DisplayName: FirstNonEmptyClaim(claims, "displayname", "display_name", "name", "cn"),
		Claims:      claims, Metadata: `{"source":"verified_saml_assertion"}`,
	}, true
}

func samlSigningKeyDescriptor(certificate *x509.Certificate) saml.KeyDescriptor {
	return saml.KeyDescriptor{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(certificate.Raw)}}}}}
}

func strictBearerConfirmation(assertion *saml.Assertion, recipient, requestID string) *saml.SubjectConfirmationData {
	var selected *saml.SubjectConfirmationData
	for index := range assertion.Subject.SubjectConfirmations {
		confirmation := &assertion.Subject.SubjectConfirmations[index]
		data := confirmation.SubjectConfirmationData
		if confirmation.Method != samlBearerConfirmationMethod || data == nil || data.Recipient != recipient || data.InResponseTo != requestID {
			continue
		}
		if selected != nil {
			return nil
		}
		selected = data
	}
	return selected
}
