package identityprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func ExchangeOAuth2Callback(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig, challenge authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, error) {
	if strings.TrimSpace(code) == "" || strings.TrimSpace(challenge.State) == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oauth2 callback code or state missing")
	}
	switch strings.ToLower(strings.TrimSpace(config.Adapter)) {
	case "generic_oauth2":
		return exchangeGenericOAuth2Identity(ctx, provider, code, config, challenge)
	case "github":
		return exchangeGitHubOAuth(ctx, provider, code, config, challenge)
	case "instagram":
		return exchangeInstagramOAuth(ctx, provider, code, config)
	case "dingtalk":
		return exchangeDingTalkOAuth(ctx, provider, code, config)
	case "wechat_web":
		return exchangeWeChatWebOAuth(ctx, provider, code, config)
	case "wecom":
		return exchangeWeComOAuth(ctx, provider, code, config)
	default:
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oauth2 adapter %q is not registered", config.Adapter)
	}
}

func exchangeInstagramOAuth(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error) {
	values := url.Values{"client_id": {config.ClientID}, "client_secret": {config.ClientSecret}, "grant_type": {"authorization_code"}, "redirect_uri": {config.RedirectURL}, "code": {strings.TrimSpace(code)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse, err := executeJSON(req, "instagram access token")
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	token := FirstNonEmptyString(tokenResponse, "access_token")
	tokenUserID := FirstNonEmptyString(tokenResponse, "user_id")
	if token == "" || tokenUserID == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("instagram token response missing identity")
	}
	userinfoURL, err := url.Parse(config.UserInfoURL)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	query := userinfoURL.Query()
	query.Set("fields", "id,username,account_type")
	query.Set("access_token", token)
	userinfoURL.RawQuery = query.Encode()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL.String(), nil)
	user, err := executeJSON(req, "instagram current user")
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	subject := FirstNonEmptyString(user, "id")
	if subject == "" || subject != tokenUserID {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("instagram user identity mismatch")
	}
	return authmodel.AuthExternalIdentityAssertion{Provider: strings.ToLower(strings.TrimSpace(provider)), Subject: subject, DisplayName: FirstNonEmptyString(user, "username"), Claims: claimsFromMap(user), Metadata: `{"source":"instagram_current_user"}`}, nil
}

func exchangeGenericOAuth2Identity(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig, challenge authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, error) {
	token, tokenClaims, err := exchangeGenericTokenWithVerifier(ctx, code, challenge.CodeVerifier, config)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	assertion, err := fetchGenericUserInfo(ctx, token, provider, config, tokenClaims)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	if strings.TrimSpace(assertion.Subject) == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oauth2 userinfo missing stable subject")
	}
	assertion.Metadata = `{"source":"oauth2_verified_userinfo"}`
	return assertion, nil
}

func exchangeGitHubOAuth(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig, challenge authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, error) {
	token, tokenClaims, err := exchangeGenericTokenWithVerifier(ctx, code, challenge.CodeVerifier, config)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	assertion, err := fetchGenericUserInfo(ctx, token, provider, config, tokenClaims)
	if err != nil || assertion.Subject == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("github verified user lookup failed: %w", err)
	}
	return assertion, nil
}

func exchangeDingTalkOAuth(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error) {
	payload, _ := json.Marshal(map[string]string{"clientId": config.ClientID, "clientSecret": config.ClientSecret, "code": strings.TrimSpace(code), "grantType": "authorization_code"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.TokenURL, bytes.NewReader(payload))
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	tokenResponse, err := executeJSON(req, "dingtalk user access token")
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	token := FirstNonEmptyString(tokenResponse, "accessToken", "access_token")
	if token == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("dingtalk token response missing access token")
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, config.UserInfoURL, nil)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	req.Header.Set("x-acs-dingtalk-access-token", token)
	user, err := executeJSON(req, "dingtalk current user")
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	claims := claimsFromMap(user)
	subject := FirstNonEmptyString(user, "unionId", "union_id", "openId", "open_id")
	if subject == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("dingtalk user response missing stable subject")
	}
	return authmodel.AuthExternalIdentityAssertion{Provider: strings.ToLower(strings.TrimSpace(provider)), Subject: subject, Email: FirstNonEmptyString(user, "email"), DisplayName: FirstNonEmptyString(user, "nick", "name"), AvatarURL: FirstNonEmptyString(user, "avatarUrl", "avatar_url"), Claims: claims, Metadata: `{"source":"dingtalk_current_user"}`}, nil
}

func exchangeWeChatWebOAuth(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error) {
	endpoint, err := url.Parse(config.TokenURL)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	query := endpoint.Query()
	query.Set("appid", config.ClientID)
	query.Set("secret", config.ClientSecret)
	query.Set("code", strings.TrimSpace(code))
	query.Set("grant_type", "authorization_code")
	endpoint.RawQuery = query.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	tokenResponse, err := executeJSON(req, "wechat web access token")
	if err != nil || (FirstNonEmptyString(tokenResponse, "errcode") != "" && FirstNonEmptyString(tokenResponse, "errcode") != "0") {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("wechat web token exchange failed: %w", err)
	}
	token, openID := FirstNonEmptyString(tokenResponse, "access_token"), FirstNonEmptyString(tokenResponse, "openid")
	if token == "" || openID == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("wechat web token response missing identity")
	}
	userinfo, _ := url.Parse(config.UserInfoURL)
	query = userinfo.Query()
	query.Set("access_token", token)
	query.Set("openid", openID)
	query.Set("lang", "zh_CN")
	userinfo.RawQuery = query.Encode()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, userinfo.String(), nil)
	user, err := executeJSON(req, "wechat web userinfo")
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	unionID := FirstNonEmptyString(user, "unionid")
	subject := unionID
	if subject == "" {
		subject = openID
	}
	claims := claimsFromMap(user)
	claims["openid"] = openID
	return authmodel.AuthExternalIdentityAssertion{Provider: strings.ToLower(strings.TrimSpace(provider)), Subject: subject, DisplayName: FirstNonEmptyString(user, "nickname"), AvatarURL: FirstNonEmptyString(user, "headimgurl"), Claims: claims, Metadata: `{"source":"wechat_web_userinfo"}`}, nil
}

func exchangeWeComOAuth(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error) {
	tokenURL, err := url.Parse(config.TokenURL)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	query := tokenURL.Query()
	query.Set("corpid", config.ClientID)
	query.Set("corpsecret", config.ClientSecret)
	tokenURL.RawQuery = query.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	tokenResponse, err := executeJSON(req, "wecom access token")
	if err != nil || stringFromAny(tokenResponse["errcode"]) != "0" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("wecom access token failed: %w", err)
	}
	token := FirstNonEmptyString(tokenResponse, "access_token")
	userinfoURL, err := url.Parse(config.UserInfoURL)
	if err != nil || token == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("wecom access token response invalid")
	}
	query = userinfoURL.Query()
	query.Set("access_token", token)
	query.Set("code", strings.TrimSpace(code))
	userinfoURL.RawQuery = query.Encode()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL.String(), nil)
	user, err := executeJSON(req, "wecom oauth userinfo")
	if err != nil || stringFromAny(user["errcode"]) != "0" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("wecom oauth userinfo failed: %w", err)
	}
	subject := FirstNonEmptyString(user, "UserId", "userid", "OpenId", "openid")
	if subject == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("wecom userinfo missing subject")
	}
	return authmodel.AuthExternalIdentityAssertion{Provider: strings.ToLower(strings.TrimSpace(provider)), Subject: subject, Claims: claimsFromMap(user), Metadata: `{"source":"wecom_oauth_userinfo"}`}, nil
}

func exchangeGenericTokenWithVerifier(ctx context.Context, code, verifier string, config authmodel.AuthProviderConfig) (string, map[string]string, error) {
	values := url.Values{"grant_type": {"authorization_code"}, "client_id": {config.ClientID}, "client_secret": {config.ClientSecret}, "code": {strings.TrimSpace(code)}, "redirect_uri": {config.RedirectURL}}
	if strings.TrimSpace(verifier) != "" {
		values.Set("code_verifier", strings.TrimSpace(verifier))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parsed, err := executeJSON(req, "oauth2 token")
	if err != nil {
		return "", nil, err
	}
	if providerError := FirstNonEmptyString(parsed, "error", "error_description"); providerError != "" {
		return "", nil, fmt.Errorf("oauth2 token error %s", providerError)
	}
	token := FirstNonEmptyString(parsed, "access_token", "token")
	if token == "" {
		return "", nil, fmt.Errorf("oauth2 token missing access_token")
	}
	return token, claimsFromMap(parsed), nil
}
