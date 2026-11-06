package identityprovider

import (
	"context"
	"errors"
	"strings"
	"testing"

	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	ldap "github.com/go-ldap/ldap/v3"
)

type ldapConnectionStub struct {
	binds  [][2]string
	search *ldap.SearchRequest
	result *ldap.SearchResult
	err    error
}

func (s *ldapConnectionStub) Bind(username, password string) error {
	s.binds = append(s.binds, [2]string{username, password})
	if len(s.binds) == 2 {
		return s.err
	}
	return nil
}

func (s *ldapConnectionStub) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	s.search = request
	return s.result, nil
}

func (*ldapConnectionStub) Close() error { return nil }

func ldapTestConfig() authmodel.AuthProviderConfig {
	return authmodel.AuthProviderConfig{
		Key: "ldap", Type: "ldap", LDAPURL: "ldaps://ad.example.com:636", LDAPBindDN: "CN=Verdent,OU=Service,DC=example,DC=com",
		ClientSecret: "bind-secret", LDAPUsersDN: "OU=People,DC=example,DC=com", LDAPUserSearchFilter: "(objectClass=user)",
		LDAPUsernameAttribute: "sAMAccountName", LDAPUUIDAttribute: "objectGUID", LDAPEmailAttribute: "mail",
		LDAPFirstNameAttribute: "givenName", LDAPLastNameAttribute: "sn",
	}
}

func TestLDAPPasswordAdapterAuthenticatesWithEscapedSearchFilter(t *testing.T) {
	entry := ldap.NewEntry("CN=Alice,OU=People,DC=example,DC=com", map[string][]string{
		"objectGUID": {"8f67b21d-97a4-4f86-8801-0e413b7c77f4"}, "mail": {"Alice@Example.com"},
		"sAMAccountName": {"alice"}, "givenName": {"Alice"}, "sn": {"Chen"},
	})
	connection := &ldapConnectionStub{result: &ldap.SearchResult{Entries: []*ldap.Entry{entry}}}
	adapter := LDAPPasswordAdapter{dial: func(context.Context, ldapProviderSettings) (ldapConnection, error) { return connection, nil }}
	login := `alice*)(mail=attacker@example.com`
	assertion, err := adapter.Authenticate(t.Context(), "ldap", ldapTestConfig(), login, "user-secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(connection.binds) != 2 || connection.binds[0][0] != ldapTestConfig().LDAPBindDN || connection.binds[1] != [2]string{entry.DN, "user-secret"} {
		t.Fatalf("binds=%#v", connection.binds)
	}
	if strings.Contains(connection.search.Filter, login) || !strings.Contains(connection.search.Filter, `alice\2a\29\28mail=attacker@example.com`) {
		t.Fatalf("unsafe or unexpected filter=%q", connection.search.Filter)
	}
	if assertion.Provider != "ldap" || assertion.Subject != "objectguid:8f67b21d-97a4-4f86-8801-0e413b7c77f4" || assertion.Email != "alice@example.com" || assertion.DisplayName != "Alice Chen" || !assertion.ProviderSubjectVerified {
		t.Fatalf("assertion=%+v", assertion)
	}
}

func TestLDAPPasswordAdapterRejectsInvalidCredentialsWithoutDirectoryDisclosure(t *testing.T) {
	entry := ldap.NewEntry("CN=Alice,OU=People,DC=example,DC=com", map[string][]string{
		"objectGUID": {"stable-id"}, "mail": {"alice@example.com"}, "sAMAccountName": {"alice"},
	})
	connection := &ldapConnectionStub{result: &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, err: &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials}}
	adapter := LDAPPasswordAdapter{dial: func(context.Context, ldapProviderSettings) (ldapConnection, error) { return connection, nil }}
	_, err := adapter.Authenticate(t.Context(), "ldap", ldapTestConfig(), "alice", "wrong")
	if !errors.Is(err, authcontract.ErrAuthProviderInvalidCredentials) {
		t.Fatalf("error=%v", err)
	}
}

func TestLDAPSettingsRequireEncryptedTransportAndValidFilter(t *testing.T) {
	config := ldapTestConfig()
	config.LDAPURL = "ldap://ad.example.com:389"
	if _, err := ldapSettings(config); err == nil || !strings.Contains(err.Error(), "StartTLS") {
		t.Fatalf("insecure LDAP error=%v", err)
	}
	config.LDAPStartTLS = true
	config.LDAPUserSearchFilter = "objectClass=user"
	if _, err := ldapSettings(config); err == nil || !strings.Contains(err.Error(), "filter") {
		t.Fatalf("invalid filter error=%v", err)
	}
}
