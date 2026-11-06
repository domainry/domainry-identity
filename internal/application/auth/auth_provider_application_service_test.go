package auth

import (
	"testing"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestMergeTypedAuthProviderCredentials(t *testing.T) {
	merged := MergeTypedAuthProviderCredentials([]map[string]any{{"key": "oidc", "type": "oidc"}}, []authmodel.AuthProviderCredential{{ProviderKey: "oidc", ClientID: "client", ClientSecret: "secret", RedirectURL: "url"}})
	if len(merged) != 1 || merged[0]["client_id"] != "client" {
		t.Fatalf("merged=%#v", merged)
	}
}

func TestMergeTypedAuthProviderCredentialsRestoresCustomProvider(t *testing.T) {
	merged := MergeTypedAuthProviderCredentials([]map[string]any{{"key": "local", "type": "password"}}, []authmodel.AuthProviderCredential{
		{ProviderKey: "partner_oidc", Type: "oidc", Issuer: "https://identity.example", AuthURL: "https://identity.example/authorize", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app.example/callback", Scope: "openid"},
		{ProviderKey: "unsafe", Type: "custom", ClientID: "client", ClientSecret: "secret"},
	})
	if len(merged) != 2 || merged[1]["key"] != "partner_oidc" || merged[1]["enabled"] != true || merged[1]["issuer"] != "https://identity.example" {
		t.Fatalf("merged=%#v", merged)
	}
	if _, leaked := merged[1]["client_secret"]; !leaked {
		// Internal merged configuration intentionally carries the secret; public
		// projection redaction is covered by AuthProviderConfig.SafeMap tests.
		t.Fatal("internal restored configuration lost encrypted credential value")
	}
}

func TestMergeTypedAuthProviderCredentialsRestoresLDAPProvider(t *testing.T) {
	merged := MergeTypedAuthProviderCredentials(nil, []authmodel.AuthProviderCredential{{
		ProviderKey: "ldap", Label: "AD / LDAP", Type: "ldap", LDAPURL: "ldaps://ad.example.com:636",
		LDAPBindDN: "CN=Verdent,DC=example,DC=com", ClientSecret: "bind-secret", LDAPUsersDN: "DC=example,DC=com",
		LDAPUserSearchFilter: "(objectClass=user)", LDAPUsernameAttribute: "sAMAccountName", LDAPUUIDAttribute: "objectGUID", LDAPEmailAttribute: "mail",
	}})
	if len(merged) != 1 || merged[0]["type"] != "ldap" || merged[0]["enabled"] != true || merged[0]["ldap_url"] != "ldaps://ad.example.com:636" {
		t.Fatalf("merged=%#v", merged)
	}
	config := authmodel.AuthProviderConfigFromMap(merged[0])
	safe := config.SafeMap()
	if safe["ldap_bind_password_configured"] != true || safe["client_secret"] != nil {
		t.Fatalf("safe LDAP provider=%#v", safe)
	}
}
