package identityprovider

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func stringFromProviderConfig(config map[string]any, key string) string {
	return stringFromAny(config[key])
}
func stringFromAny(value any) string {
	if value == nil {
		return ""
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "<nil>" {
		return ""
	}
	return text
}

type samlXMLResponse struct {
	XMLName   xml.Name
	Assertion samlXMLAssertion `xml:"Assertion"`
	Signature samlXMLSignature `xml:"Signature"`
}

type samlXMLAssertion struct {
	XMLName            xml.Name
	Subject            samlXMLSubject            `xml:"Subject"`
	Conditions         samlXMLConditions         `xml:"Conditions"`
	AttributeStatement samlXMLAttributeStatement `xml:"AttributeStatement"`
	Signature          samlXMLSignature          `xml:"Signature"`
}

type samlXMLSubject struct {
	NameID              string                     `xml:"NameID"`
	SubjectConfirmation samlXMLSubjectConfirmation `xml:"SubjectConfirmation"`
}

type samlXMLSubjectConfirmation struct {
	Data samlXMLSubjectConfirmationData `xml:"SubjectConfirmationData"`
}

type samlXMLSubjectConfirmationData struct {
	InResponseTo string `xml:"InResponseTo,attr"`
	Recipient    string `xml:"Recipient,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
}

type samlXMLConditions struct {
	NotBefore           string                     `xml:"NotBefore,attr"`
	NotOnOrAfter        string                     `xml:"NotOnOrAfter,attr"`
	AudienceRestriction samlXMLAudienceRestriction `xml:"AudienceRestriction"`
}

type samlXMLAudienceRestriction struct {
	Audience string `xml:"Audience"`
}

type samlXMLAttributeStatement struct {
	Attributes []samlXMLAttribute `xml:"Attribute"`
}

type samlXMLAttribute struct {
	Name         string   `xml:"Name,attr"`
	FriendlyName string   `xml:"FriendlyName,attr"`
	Values       []string `xml:"AttributeValue"`
}

type samlXMLSignature struct {
	SignatureValue string `xml:"SignatureValue"`
}

func VerifySAMLXMLResponse(provider string, encodedResponse string, config map[string]any, challenge authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, bool) {
	assertion, responseSignature, ok := parseSAMLXMLAssertion(encodedResponse)
	if !ok {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	subject := strings.TrimSpace(assertion.Subject.NameID)
	audience := strings.TrimSpace(assertion.Conditions.AudienceRestriction.Audience)
	destination := strings.TrimSpace(assertion.Subject.SubjectConfirmation.Data.Recipient)
	inResponseTo := strings.TrimSpace(assertion.Subject.SubjectConfirmation.Data.InResponseTo)
	notBefore := strings.TrimSpace(assertion.Conditions.NotBefore)
	notOnOrAfter := strings.TrimSpace(assertion.Conditions.NotOnOrAfter)
	if notOnOrAfter == "" {
		notOnOrAfter = strings.TrimSpace(assertion.Subject.SubjectConfirmation.Data.NotOnOrAfter)
	}
	signature := strings.TrimSpace(assertion.Signature.SignatureValue)
	if signature == "" {
		signature = strings.TrimSpace(responseSignature.SignatureValue)
	}
	if subject == "" || !samlXMLAssertionValid(config, challenge, encodedResponse, subject, audience, destination, inResponseTo, notBefore, notOnOrAfter, signature) {
		return authmodel.AuthExternalIdentityAssertion{}, false
	}
	claims := samlXMLAttributeClaims(assertion.AttributeStatement)
	claims["name_id"] = subject
	claims["audience"] = audience
	claims["destination"] = destination
	claims["in_response_to"] = inResponseTo
	email := FirstNonEmptyClaim(claims, "email", "emailaddress", "mail")
	displayName := FirstNonEmptyClaim(claims, "display_name", "displayname", "name", "cn")
	return authmodel.AuthExternalIdentityAssertion{
		Provider:    provider,
		Subject:     subject,
		Email:       email,
		DisplayName: displayName,
		Claims:      claims,
		Metadata:    `{"source":"saml_xml_callback"}`,
	}, true
}

func parseSAMLXMLAssertion(encodedResponse string) (samlXMLAssertion, samlXMLSignature, bool) {
	payload := strings.TrimSpace(encodedResponse)
	if payload == "" || len(payload) > 1<<20 {
		return samlXMLAssertion{}, samlXMLSignature{}, false
	}
	var data []byte
	if strings.HasPrefix(payload, "<") {
		data = []byte(payload)
	} else {
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(payload)
		}
		if err != nil {
			return samlXMLAssertion{}, samlXMLSignature{}, false
		}
		data = decoded
	}
	var probe struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(data, &probe); err != nil {
		return samlXMLAssertion{}, samlXMLSignature{}, false
	}
	if probe.XMLName.Local == "Assertion" {
		var assertion samlXMLAssertion
		_ = xml.Unmarshal(data, &assertion)
		return assertion, samlXMLSignature{}, true
	}
	var response samlXMLResponse
	_ = xml.Unmarshal(data, &response)
	if response.Assertion.XMLName.Local != "Assertion" {
		return samlXMLAssertion{}, samlXMLSignature{}, false
	}
	return response.Assertion, response.Signature, true
}

func samlXMLAssertionValid(config map[string]any, challenge authmodel.AuthProviderChallenge, encodedResponse string, subject string, audience string, destination string, inResponseTo string, notBefore string, notOnOrAfter string, signature string) bool {
	if !MockSAMLAssertionValid(config, challenge, subject, audience, destination, inResponseTo, notBefore, notOnOrAfter, "mock-signature:"+subject+":"+audience) {
		return false
	}
	if certificates := samlProviderCertificates(config); len(certificates) > 0 {
		return samlXMLDSigVerified(encodedResponse, certificates)
	}
	return false
}

func samlProviderCertificates(config map[string]any) []*x509.Certificate {
	material := strings.TrimSpace(stringFromProviderConfig(config, "client_secret"))
	if material == "" {
		return nil
	}
	var certificates []*x509.Certificate
	remaining := []byte(material)
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certificates = append(certificates, cert)
		}
	}
	return certificates
}

func samlXMLDSigVerified(encodedResponse string, certificates []*x509.Certificate) bool {
	payload, ok := decodeSAMLXMLPayload(encodedResponse)
	if !ok {
		return false
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(payload); err != nil {
		return false
	}
	root := doc.Root()
	if root == nil {
		return false
	}
	store := &dsig.MemoryX509CertificateStore{Roots: certificates}
	ctx := dsig.NewDefaultValidationContext(store)
	ctx.IdAttribute = "ID"
	for _, candidate := range samlXMLSignatureCandidates(root) {
		if err := validateSAMLXMLSignature(ctx, candidate); err == nil {
			return true
		}
	}
	return false
}

var validateSAMLXMLSignature = func(ctx *dsig.ValidationContext, candidate *etree.Element) error {
	_, err := ctx.Validate(candidate)
	return err
}

func decodeSAMLXMLPayload(encodedResponse string) ([]byte, bool) {
	payload := strings.TrimSpace(encodedResponse)
	if payload == "" || len(payload) > 1<<20 {
		return nil, false
	}
	if strings.HasPrefix(payload, "<") {
		return []byte(payload), true
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(payload)
	}
	if err != nil {
		return nil, false
	}
	return decoded, true
}

func samlXMLSignatureCandidates(root *etree.Element) []*etree.Element {
	var candidates []*etree.Element
	var visit func(*etree.Element)
	visit = func(el *etree.Element) {
		if el == nil {
			return
		}
		if samlXMLLocalName(el.Tag) == "Assertion" || samlXMLLocalName(el.Tag) == "Response" {
			if samlXMLHasSignature(el) {
				candidates = append(candidates, el)
			}
		}
		for _, child := range el.ChildElements() {
			visit(child)
		}
	}
	visit(root)
	return candidates
}

func samlXMLHasSignature(el *etree.Element) bool {
	for _, child := range el.ChildElements() {
		if samlXMLLocalName(child.Tag) == "Signature" {
			return true
		}
	}
	return false
}

func samlXMLLocalName(tag string) string {
	if at := strings.LastIndex(tag, ":"); at >= 0 && at < len(tag)-1 {
		return tag[at+1:]
	}
	return tag
}

func expectedSAMLXMLSignature(config map[string]any, subject string, audience string, destination string, inResponseTo string, notBefore string, notOnOrAfter string) string {
	material := strings.TrimSpace(stringFromProviderConfig(config, "client_secret"))
	if material == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(subject),
		strings.TrimSpace(audience),
		strings.TrimSpace(destination),
		strings.TrimSpace(inResponseTo),
		strings.TrimSpace(notBefore),
		strings.TrimSpace(notOnOrAfter),
		material,
	}, "|")))
	return "saml-sha256:" + hex.EncodeToString(digest[:])
}

func samlXMLAttributeClaims(statement samlXMLAttributeStatement) map[string]string {
	claims := map[string]string{}
	for _, attr := range statement.Attributes {
		keySource := strings.TrimSpace(attr.FriendlyName)
		if keySource == "" {
			keySource = strings.TrimSpace(attr.Name)
		}
		key := strings.ToLower(keySource)
		key = strings.ReplaceAll(key, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/", "")
		key = strings.ReplaceAll(key, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims", "")
		key = strings.ReplaceAll(key, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims:", "")
		key = strings.ReplaceAll(key, " ", "_")
		if key == "" || len(attr.Values) == 0 {
			continue
		}
		value := strings.TrimSpace(attr.Values[0])
		if value == "" {
			continue
		}
		claims[key] = value
	}
	if email := strings.ToLower(strings.TrimSpace(FirstNonEmptyClaim(claims, "email", "emailaddress", "mail"))); email != "" {
		if at := strings.LastIndex(email, "@"); at >= 0 && at < len(email)-1 {
			claims["email_domain"] = email[at+1:]
		}
	}
	return claims
}

func FirstNonEmptyClaim(claims map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(claims[strings.ToLower(key)]); value != "" {
			return value
		}
	}
	return ""
}

func FirstNonEmptyString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(stringFromAny(values[key])); value != "" {
			return value
		}
	}
	return ""
}

func MockOIDCClaimsValid(config map[string]any, challenge authmodel.AuthProviderChallenge, issuer string, audience string, nonce string) bool {
	expectedIssuer := stringFromProviderConfig(config, "issuer")
	expectedAudience := stringFromProviderConfig(config, "client_id")
	if expectedIssuer == "" || expectedAudience == "" || strings.TrimSpace(challenge.Nonce) == "" {
		return false
	}
	return issuer == expectedIssuer && audience == expectedAudience && nonce == challenge.Nonce
}

func MockSAMLAssertionValid(config map[string]any, challenge authmodel.AuthProviderChallenge, subject string, audience string, destination string, inResponseTo string, notBefore string, notOnOrAfter string, signature string) bool {
	expectedAudience := stringFromProviderConfig(config, "client_id")
	expectedDestination := stringFromProviderConfig(config, "redirect_url")
	if expectedAudience == "" || expectedDestination == "" || strings.TrimSpace(challenge.State) == "" {
		return false
	}
	if audience != expectedAudience || destination != expectedDestination || inResponseTo != challenge.State {
		return false
	}
	if signature != "mock-signature:"+subject+":"+expectedAudience {
		return false
	}
	now := time.Now().UTC()
	if notBeforeTime, ok := parseSAMLMockTime(notBefore); !ok || now.Add(2*time.Minute).Before(notBeforeTime) {
		return false
	}
	if notOnOrAfterTime, ok := parseSAMLMockTime(notOnOrAfter); !ok || !now.Before(notOnOrAfterTime.Add(2*time.Minute)) {
		return false
	}
	return true
}

func parseSAMLMockTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}
