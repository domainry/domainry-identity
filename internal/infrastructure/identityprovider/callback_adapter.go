package identityprovider

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"fmt"
	"strings"
)

type CallbackAdapter struct {
	VerifySAMLResponse   func(string, string, map[string]any, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, bool)
	ExchangeOIDCCallback func(context.Context, string, string, authmodel.AuthProviderConfig, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, error)
}

func (a CallbackAdapter) Exchange(ctx context.Context, provider string, config authmodel.AuthProviderConfig, challenge authmodel.AuthProviderChallenge, input authmodel.AuthProviderCallbackInput) (authmodel.AuthExternalIdentityAssertion, error) {
	verifySAML := a.VerifySAMLResponse
	if verifySAML == nil {
		verifySAML = VerifyStrictSAMLResponse
	}
	exchangeOIDC := a.ExchangeOIDCCallback
	if exchangeOIDC == nil {
		exchangeOIDC = ExchangeOIDCCallback
	}
	if config.Type == "saml" {
		return a.exchangeSAML(ctx, provider, config.Map(), challenge, input.Values, verifySAML)
	}
	return exchangeOIDC(ctx, provider, strings.TrimSpace(input.Values["code"]), config, challenge)
}

func (CallbackAdapter) exchangeSAML(ctx context.Context, provider string, config map[string]any, challenge authmodel.AuthProviderChallenge, values map[string]string, verify func(string, string, map[string]any, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, bool)) (authmodel.AuthExternalIdentityAssertion, error) {
	if err := ctx.Err(); err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	assertion, ok := verify(provider, strings.TrimSpace(values["SAMLResponse"]), config, challenge)
	if err := ctx.Err(); err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	if !ok {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("auth.provider_token_exchange_not_configured")
	}
	return assertion, nil
}
