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
	CodeExchanges        map[string]func(context.Context, string, string, authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error)
	OAuthExchanges       map[string]func(context.Context, string, string, authmodel.AuthProviderConfig, authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, error)
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
	if config.Type == "oauth2" {
		adapter := strings.ToLower(strings.TrimSpace(config.Adapter))
		if adapter == "" {
			adapter = strings.ToLower(strings.TrimSpace(provider))
		}
		if custom := a.OAuthExchanges[adapter]; custom != nil {
			assertion, err := custom(ctx, provider, strings.TrimSpace(input.Values["code"]), config, challenge)
			if err != nil {
				return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("auth.provider_token_exchange_failed: %w", err)
			}
			return assertion, nil
		}
		assertion, err := ExchangeOAuth2Callback(ctx, provider, strings.TrimSpace(input.Values["code"]), config, challenge)
		if err != nil {
			return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("auth.provider_token_exchange_failed: %w", err)
		}
		return assertion, nil
	}
	return exchangeOIDC(ctx, provider, strings.TrimSpace(input.Values["code"]), config, challenge)
}

func (a CallbackAdapter) ExchangeCode(ctx context.Context, provider string, config authmodel.AuthProviderConfig, code string) (authmodel.AuthExternalIdentityAssertion, error) {
	if !strings.EqualFold(config.Type, "code_exchange") && !strings.EqualFold(config.Type, "wechat_mini_program") {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("auth.provider_exchange_not_supported")
	}
	adapter := strings.ToLower(strings.TrimSpace(config.Adapter))
	if adapter == "" {
		adapter = strings.ToLower(strings.TrimSpace(provider))
	}
	if custom := a.CodeExchanges[adapter]; custom != nil {
		return custom(ctx, provider, code, config)
	}
	switch adapter {
	case "wechat_mini_program":
		return ExchangeWeChatMiniProgramCode(ctx, provider, code, config)
	case "line_liff":
		return ExchangeLineLIFFIDToken(ctx, provider, code, config)
	case "alipay_mini_program":
		return ExchangeAlipayMiniProgramCode(ctx, provider, code, config)
	default:
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("auth provider code exchange adapter %q is not registered", adapter)
	}
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
