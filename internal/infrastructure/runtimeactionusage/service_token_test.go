package runtimeactionusage

import (
	"context"
	"testing"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type tokenIssuerStub struct {
	calls   int
	request identitysdk.ExchangeApplicationServiceTokenRequest
	token   identitysdk.ApplicationServiceToken
	err     error
}

func (issuer *tokenIssuerStub) IssueApplicationServiceToken(_ context.Context, request identitysdk.ExchangeApplicationServiceTokenRequest, credentialID string) (identitysdk.ApplicationServiceToken, error) {
	issuer.calls++
	issuer.request = request
	token := issuer.token
	token.CredentialID = credentialID
	return token, issuer.err
}

func TestApplicationServiceTokenSourceCachesOnlyValidNarrowToken(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	application := identitysdk.ApplicationRef{TenantID: "workspace-a", WorkspaceID: "workspace-a", ApplicationKey: "domainry-identity-control-plane"}
	grant := identitysdk.ApplicationServiceGrant{Resource: "runtime.action.permission_usages", Action: "query"}
	issuer := &tokenIssuerStub{token: identitysdk.ApplicationServiceToken{
		AccessToken: "short-lived-token", TokenType: "Bearer", ExpiresAt: now.Add(5 * time.Minute),
		Application: application, Audience: "domainry-runtime", Grants: []identitysdk.ApplicationServiceGrant{grant},
	}}
	source, err := NewApplicationServiceTokenSource(issuer, ServiceTokenOptions{
		Application: application, Audience: "domainry-runtime", Grant: grant, CredentialID: "identity-action-usage", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.AccessToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.AccessToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first != "short-lived-token" || second != first || issuer.calls != 1 || issuer.request.Application != application || issuer.request.Audience != "domainry-runtime" || len(issuer.request.Grants) != 1 || issuer.request.Grants[0] != grant {
		t.Fatalf("first=%q second=%q calls=%d request=%+v", first, second, issuer.calls, issuer.request)
	}
}

func TestApplicationServiceTokenSourceRejectsAuthorityDrift(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	application := identitysdk.ApplicationRef{TenantID: "workspace-a", WorkspaceID: "workspace-a", ApplicationKey: "domainry-identity-control-plane"}
	grant := identitysdk.ApplicationServiceGrant{Resource: "runtime.action.permission_usages", Action: "query"}
	issuer := &tokenIssuerStub{token: identitysdk.ApplicationServiceToken{
		AccessToken: "wrong-token", TokenType: "Bearer", ExpiresAt: now.Add(5 * time.Minute),
		Application: application, Audience: "other-runtime", Grants: []identitysdk.ApplicationServiceGrant{grant},
	}}
	source, err := NewApplicationServiceTokenSource(issuer, ServiceTokenOptions{
		Application: application, Audience: "domainry-runtime", Grant: grant, CredentialID: "identity-action-usage", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.AccessToken(t.Context()); err == nil {
		t.Fatal("service token with another audience was accepted")
	}
}
