package identityprovider

import (
	"errors"
	"os"
	"strings"
	"testing"

	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestLDAPPasswordAdapterAgainstRealSambaAD(t *testing.T) {
	if os.Getenv("IDENTITY_LDAP_INTEGRATION") != "1" {
		t.Skip("set IDENTITY_LDAP_INTEGRATION=1 to run against the Docker Samba AD lab")
	}
	certificatePath := strings.TrimSpace(os.Getenv("IDENTITY_LDAP_CA_FILE"))
	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatalf("read LDAP CA certificate %q: %v", certificatePath, err)
	}
	config := authmodel.AuthProviderConfig{
		Key:                    "ldap",
		Type:                   "ldap",
		LDAPURL:                envOrDefault("IDENTITY_LDAP_URL", "ldaps://localhost:1636"),
		LDAPBindDN:             "CN=Verdent Directory,CN=Users,DC=verdent,DC=test",
		ClientSecret:           "Domainry!123",
		LDAPUsersDN:            "CN=Users,DC=verdent,DC=test",
		LDAPUserSearchFilter:   "(&(objectCategory=person)(objectClass=user))",
		LDAPUsernameAttribute:  "sAMAccountName",
		LDAPUUIDAttribute:      "objectGUID",
		LDAPEmailAttribute:     "mail",
		LDAPFirstNameAttribute: "givenName",
		LDAPLastNameAttribute:  "sn",
		VerificationKey:        string(certificate),
	}
	adapter := LDAPPasswordAdapter{}
	if err := adapter.Probe(t.Context(), config); err != nil {
		t.Fatalf("probe real Samba AD: %v", err)
	}
	assertion, err := adapter.Authenticate(t.Context(), "ldap", config, "alice", "Domainry!123")
	if err != nil {
		t.Fatalf("authenticate real Samba AD user: %v", err)
	}
	if assertion.Email != "alice@example.com" || assertion.DisplayName != "Alice Chen" || !strings.HasPrefix(assertion.Subject, "objectguid:") || !assertion.ProviderSubjectVerified {
		t.Fatalf("unexpected real Samba AD assertion: %#v", assertion)
	}
	emailAssertion, err := adapter.Authenticate(t.Context(), "ldap", config, "alice@example.com", "Domainry!123")
	if err != nil || emailAssertion.Subject != assertion.Subject {
		t.Fatalf("authenticate real Samba AD user by email: assertion=%#v err=%v", emailAssertion, err)
	}
	_, err = adapter.Authenticate(t.Context(), "ldap", config, "alice", "wrong-password")
	if !errors.Is(err, authcontract.ErrAuthProviderInvalidCredentials) {
		t.Fatalf("wrong password error=%v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
