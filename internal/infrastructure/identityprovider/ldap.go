package identityprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	ldap "github.com/go-ldap/ldap/v3"
)

const (
	ldapDialTimeout    = 5 * time.Second
	ldapRequestTimeout = 10 * time.Second
)

var ldapAttributePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

type ldapConnection interface {
	Bind(string, string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

type ldapProviderSettings struct {
	url                string
	bindDN             string
	bindPassword       string
	usersDN            string
	userSearchFilter   string
	usernameAttribute  string
	uuidAttribute      string
	emailAttribute     string
	firstNameAttribute string
	lastNameAttribute  string
	tlsConfig          *tls.Config
	startTLS           bool
}

// LDAPPasswordAdapter keeps directory credentials inside the server-side Auth
// boundary. The zero value is production-ready; dial is only replaceable by
// same-package tests.
type LDAPPasswordAdapter struct {
	dial func(context.Context, ldapProviderSettings) (ldapConnection, error)
}

func (a LDAPPasswordAdapter) Authenticate(ctx context.Context, provider string, config authmodel.AuthProviderConfig, login, password string) (authmodel.AuthExternalIdentityAssertion, error) {
	if strings.TrimSpace(login) == "" || password == "" {
		return authmodel.AuthExternalIdentityAssertion{}, authcontract.ErrAuthProviderInvalidCredentials
	}
	settings, err := ldapSettings(config)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("%w: %v", authcontract.ErrAuthProviderUnavailable, err)
	}
	connection, err := a.open(ctx, settings)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("%w: connect directory: %v", authcontract.ErrAuthProviderUnavailable, err)
	}
	defer connection.Close()
	if err := contextErr(ctx); err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	if err := connection.Bind(settings.bindDN, settings.bindPassword); err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("%w: bind directory service account: %v", authcontract.ErrAuthProviderUnavailable, err)
	}
	filter := ldapUserFilter(settings, login)
	result, err := connection.Search(ldap.NewSearchRequest(
		settings.usersDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(ldapRequestTimeout/time.Second), false,
		filter, ldapRequestedAttributes(settings), nil,
	))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return authmodel.AuthExternalIdentityAssertion{}, authcontract.ErrAuthProviderInvalidCredentials
		}
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("%w: search directory user: %v", authcontract.ErrAuthProviderUnavailable, err)
	}
	if len(result.Entries) != 1 || strings.TrimSpace(result.Entries[0].DN) == "" {
		return authmodel.AuthExternalIdentityAssertion{}, authcontract.ErrAuthProviderInvalidCredentials
	}
	entry := result.Entries[0]
	if err := connection.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) || ldap.IsErrorWithCode(err, ldap.ErrorEmptyPassword) {
			return authmodel.AuthExternalIdentityAssertion{}, authcontract.ErrAuthProviderInvalidCredentials
		}
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("%w: bind directory user: %v", authcontract.ErrAuthProviderUnavailable, err)
	}
	assertion, err := ldapAssertion(strings.TrimSpace(provider), settings, entry)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("%w: %v", authcontract.ErrAuthProviderUnavailable, err)
	}
	return assertion, nil
}

func (a LDAPPasswordAdapter) Probe(ctx context.Context, config authmodel.AuthProviderConfig) error {
	settings, err := ldapSettings(config)
	if err != nil {
		return err
	}
	connection, err := a.open(ctx, settings)
	if err != nil {
		return fmt.Errorf("connect directory: %w", err)
	}
	defer connection.Close()
	if err := connection.Bind(settings.bindDN, settings.bindPassword); err != nil {
		return fmt.Errorf("bind directory service account: %w", err)
	}
	result, err := connection.Search(ldap.NewSearchRequest(
		settings.usersDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, int(ldapRequestTimeout/time.Second), false,
		settings.userSearchFilter, []string{settings.uuidAttribute}, nil,
	))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return fmt.Errorf("search directory users: %w", err)
	}
	if result == nil || len(result.Entries) == 0 {
		return fmt.Errorf("directory search returned no users")
	}
	return nil
}

func (a LDAPPasswordAdapter) open(ctx context.Context, settings ldapProviderSettings) (ldapConnection, error) {
	if a.dial != nil {
		return a.dial(ctx, settings)
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	connection, err := ldap.DialURL(settings.url, ldap.DialWithDialer(&net.Dialer{Timeout: ldapDialTimeout}), ldap.DialWithTLSConfig(settings.tlsConfig))
	if err != nil {
		return nil, err
	}
	connection.SetTimeout(ldapRequestTimeout)
	if settings.startTLS {
		if err := connection.StartTLS(settings.tlsConfig); err != nil {
			connection.Close()
			return nil, err
		}
	}
	return connection, nil
}

func ldapSettings(config authmodel.AuthProviderConfig) (ldapProviderSettings, error) {
	parsed, err := url.Parse(strings.TrimSpace(config.LDAPURL))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return ldapProviderSettings{}, fmt.Errorf("ldap_url must be an LDAP server URL without path, query, credentials, or fragment")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "ldap" && scheme != "ldaps" {
		return ldapProviderSettings{}, fmt.Errorf("ldap_url scheme must be ldap or ldaps")
	}
	if scheme == "ldap" && !config.LDAPStartTLS {
		return ldapProviderSettings{}, fmt.Errorf("ldap connections must enable StartTLS")
	}
	if scheme == "ldaps" && config.LDAPStartTLS {
		return ldapProviderSettings{}, fmt.Errorf("StartTLS cannot be combined with ldaps")
	}
	settings := ldapProviderSettings{
		url: strings.TrimSpace(config.LDAPURL), bindDN: strings.TrimSpace(config.LDAPBindDN), bindPassword: config.ClientSecret,
		usersDN: strings.TrimSpace(config.LDAPUsersDN), userSearchFilter: strings.TrimSpace(config.LDAPUserSearchFilter),
		usernameAttribute: strings.TrimSpace(config.LDAPUsernameAttribute), uuidAttribute: strings.TrimSpace(config.LDAPUUIDAttribute),
		emailAttribute: strings.TrimSpace(config.LDAPEmailAttribute), firstNameAttribute: strings.TrimSpace(config.LDAPFirstNameAttribute),
		lastNameAttribute: strings.TrimSpace(config.LDAPLastNameAttribute), startTLS: config.LDAPStartTLS,
	}
	if settings.bindDN == "" || settings.bindPassword == "" || settings.usersDN == "" || settings.userSearchFilter == "" {
		return ldapProviderSettings{}, fmt.Errorf("bind DN, bind password, users DN, and user search filter are required")
	}
	if _, err := ldap.CompileFilter(settings.userSearchFilter); err != nil {
		return ldapProviderSettings{}, fmt.Errorf("invalid user search filter: %w", err)
	}
	for name, value := range map[string]string{
		"username": settings.usernameAttribute, "UUID": settings.uuidAttribute, "email": settings.emailAttribute,
	} {
		if !ldapAttributePattern.MatchString(value) {
			return ldapProviderSettings{}, fmt.Errorf("%s attribute is invalid", name)
		}
	}
	for name, value := range map[string]string{"first name": settings.firstNameAttribute, "last name": settings.lastNameAttribute} {
		if value != "" && !ldapAttributePattern.MatchString(value) {
			return ldapProviderSettings{}, fmt.Errorf("%s attribute is invalid", name)
		}
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if certificate := strings.TrimSpace(config.VerificationKey); certificate != "" && !rootCAs.AppendCertsFromPEM([]byte(certificate)) {
		return ldapProviderSettings{}, fmt.Errorf("LDAP CA certificate is not valid PEM")
	}
	settings.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname(), RootCAs: rootCAs}
	return settings, nil
}

func ldapUserFilter(settings ldapProviderSettings, login string) string {
	escaped := ldap.EscapeFilter(strings.TrimSpace(login))
	return "(&" + settings.userSearchFilter + "(|(" + settings.usernameAttribute + "=" + escaped + ")(" + settings.emailAttribute + "=" + escaped + ")))"
}

func ldapRequestedAttributes(settings ldapProviderSettings) []string {
	values := []string{settings.uuidAttribute, settings.emailAttribute, settings.usernameAttribute}
	if settings.firstNameAttribute != "" {
		values = append(values, settings.firstNameAttribute)
	}
	if settings.lastNameAttribute != "" {
		values = append(values, settings.lastNameAttribute)
	}
	return values
}

func ldapAssertion(provider string, settings ldapProviderSettings, entry *ldap.Entry) (authmodel.AuthExternalIdentityAssertion, error) {
	subject := ldapSubject(entry.GetRawAttributeValue(settings.uuidAttribute))
	email := strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(settings.emailAttribute)))
	address, err := mail.ParseAddress(email)
	if subject == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("directory user has no stable UUID")
	}
	if err != nil || address.Address != email || !strings.Contains(email, "@") {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("directory user has no valid email")
	}
	username := strings.TrimSpace(entry.GetAttributeValue(settings.usernameAttribute))
	firstName := strings.TrimSpace(entry.GetAttributeValue(settings.firstNameAttribute))
	lastName := strings.TrimSpace(entry.GetAttributeValue(settings.lastNameAttribute))
	displayName := strings.TrimSpace(firstName + " " + lastName)
	if displayName == "" {
		displayName = username
	}
	return authmodel.AuthExternalIdentityAssertion{
		Provider: provider, Subject: strings.ToLower(settings.uuidAttribute) + ":" + subject, Email: email, DisplayName: displayName,
		Metadata: `{"source":"ldap_verified_bind"}`, ProviderSubjectVerified: true,
		Claims: map[string]string{"email": email, "username": username, "first_name": firstName, "last_name": lastName},
	}, nil
}

func ldapSubject(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	if utf8.Valid(value) {
		text := strings.TrimSpace(string(value))
		printable := text != ""
		for _, character := range text {
			if !unicode.IsPrint(character) {
				printable = false
				break
			}
		}
		if printable {
			return text
		}
	}
	return hex.EncodeToString(value)
}

func contextErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
