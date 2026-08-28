package identityprovider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

const weChatMiniProgramCodeExchangeURL = "https://api.weixin.qq.com/sns/jscode2session"

// ExchangeWeChatMiniProgramCode exchanges the one-time code returned by
// wx.login. The upstream session_key is intentionally never projected into
// the assertion because it is a provider credential, not an identity claim.
func ExchangeWeChatMiniProgramCode(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error) {
	code = strings.TrimSpace(code)
	if code == "" || strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("wechat mini program code, app id and secret are required")
	}
	endpoint := strings.TrimSpace(config.TokenURL)
	if endpoint == "" {
		endpoint = weChatMiniProgramCodeExchangeURL
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.Fragment != "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("wechat mini program token_url is invalid")
	}
	query := parsed.Query()
	query.Set("appid", strings.TrimSpace(config.ClientID))
	query.Set("secret", config.ClientSecret)
	query.Set("js_code", code)
	query.Set("grant_type", "authorization_code")
	parsed.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	req.Header.Set("Accept", "application/json")
	response, err := executeJSON(req, "wechat jscode2session")
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	if providerError := strings.TrimSpace(stringFromAny(response["errcode"])); providerError != "" && providerError != "0" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("wechat jscode2session rejected code %s", providerError)
	}
	openID := strings.TrimSpace(stringFromAny(response["openid"]))
	unionID := strings.TrimSpace(stringFromAny(response["unionid"]))
	subject := unionID
	if subject == "" {
		subject = openID
	}
	if subject == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("wechat jscode2session missing openid")
	}
	claims := map[string]string{}
	if openID != "" {
		claims["openid"] = openID
	}
	if unionID != "" {
		claims["unionid"] = unionID
	}
	return authmodel.AuthExternalIdentityAssertion{
		Provider: strings.ToLower(strings.TrimSpace(provider)), Subject: subject,
		Claims: claims, Metadata: `{"source":"wechat_jscode2session"}`,
	}, nil
}
