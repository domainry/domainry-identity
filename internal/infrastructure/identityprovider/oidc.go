package identityprovider

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var callbackHTTPClient = &http.Client{Timeout: 8 * time.Second}

// ExchangeOIDCCallback performs the provider-specific token and user-info
// exchange without depending on HTTP transport request types.
func ExchangeOIDCCallback(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig, challenge authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, error) {
	if strings.TrimSpace(code) == "" || strings.TrimSpace(challenge.State) == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("provider callback code or state missing")
	}
	if isFeishu(provider) {
		token, err := exchangeFeishuToken(ctx, code, config)
		if err != nil {
			return authmodel.AuthExternalIdentityAssertion{}, err
		}
		assertion, err := fetchFeishuUserInfo(ctx, token, config)
		assertion.Provider = strings.ToLower(strings.TrimSpace(provider))
		return assertion, err
	}
	return exchangeStandardOIDC(ctx, provider, code, config, challenge)
}

func exchangeStandardOIDC(ctx context.Context, providerKey, code string, config authmodel.AuthProviderConfig, challenge authmodel.AuthProviderChallenge) (authmodel.AuthExternalIdentityAssertion, error) {
	issuer := strings.TrimRight(strings.TrimSpace(config.Issuer), "/")
	if issuer == "" || strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.RedirectURL) == "" || strings.TrimSpace(challenge.Nonce) == "" || strings.TrimSpace(challenge.CodeVerifier) == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc issuer, client, redirect, nonce and PKCE verifier are required")
	}
	parsedIssuer, err := url.Parse(issuer)
	if err != nil || parsedIssuer.Scheme != "https" || parsedIssuer.Host == "" || parsedIssuer.User != nil || parsedIssuer.Fragment != "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc issuer must be a canonical HTTPS URL")
	}
	providerContext := oidc.ClientContext(ctx, callbackHTTPClient)
	discovered, err := oidc.NewProvider(providerContext, issuer)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc discovery failed: %w", err)
	}
	endpoint := discovered.Endpoint()
	if config.AuthURL != "" && strings.TrimSpace(config.AuthURL) != endpoint.AuthURL || config.TokenURL != "" && strings.TrimSpace(config.TokenURL) != endpoint.TokenURL {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc configured endpoints do not exactly match discovery")
	}
	oauthConfig := oauth2.Config{ClientID: strings.TrimSpace(config.ClientID), ClientSecret: config.ClientSecret, Endpoint: endpoint, RedirectURL: strings.TrimSpace(config.RedirectURL), Scopes: strings.Fields(config.Scope)}
	token, err := oauthConfig.Exchange(providerContext, strings.TrimSpace(code), oauth2.SetAuthURLParam("code_verifier", strings.TrimSpace(challenge.CodeVerifier)))
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc token exchange failed: %w", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if strings.TrimSpace(rawIDToken) == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc token response missing id_token")
	}
	verified, err := discovered.Verifier(&oidc.Config{ClientID: strings.TrimSpace(config.ClientID)}).Verify(providerContext, rawIDToken)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc id_token invalid: %w", err)
	}
	var standard struct {
		Nonce             string   `json:"nonce"`
		AuthorizedParty   string   `json:"azp"`
		IssuedAt          int64    `json:"iat"`
		Email             string   `json:"email"`
		EmailVerified     bool     `json:"email_verified"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Picture           string   `json:"picture"`
		Groups            []string `json:"groups"`
		Roles             []string `json:"roles"`
	}
	if err := verified.Claims(&standard); err != nil || standard.Nonce != challenge.Nonce || standard.IssuedAt > time.Now().Add(time.Minute).Unix() || (standard.AuthorizedParty != "" || len(verified.Audience) > 1) && standard.AuthorizedParty != config.ClientID {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc id_token claims invalid")
	}
	if verified.AccessTokenHash != "" && verified.VerifyAccessToken(token.AccessToken) != nil {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc access token binding invalid")
	}
	var raw map[string]any
	_ = verified.Claims(&raw)
	claims := claimsFromMap(raw)
	if discovered.UserInfoEndpoint() != "" {
		userInfo, userInfoErr := discovered.UserInfo(providerContext, oauth2.StaticTokenSource(token))
		if userInfoErr != nil {
			return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc userinfo failed: %w", userInfoErr)
		}
		if userInfo.Subject != verified.Subject {
			return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc userinfo subject mismatch")
		}
		var userInfoClaims map[string]any
		if userInfo.Claims(&userInfoClaims) == nil {
			for key, value := range claimsFromMap(userInfoClaims) {
				claims[key] = value
			}
		}
	}
	claims["issuer"] = verified.Issuer
	return authmodel.AuthExternalIdentityAssertion{
		Provider: strings.ToLower(strings.TrimSpace(providerKey)), Subject: verified.Subject,
		Email: FirstNonEmptyClaim(claims, "email"), DisplayName: FirstNonEmptyClaim(claims, "name", "preferred_username", "email"),
		AvatarURL: FirstNonEmptyClaim(claims, "picture"), Claims: claims, Metadata: `{"source":"verified_oidc_id_token"}`,
	}, nil
}

func isFeishu(provider string) bool {
	return strings.EqualFold(provider, "feishu") || strings.EqualFold(provider, "lark")
}

func exchangeGenericToken(ctx context.Context, code string, config authmodel.AuthProviderConfig) (string, map[string]string, error) {
	if config.TokenURL == "" {
		return "", nil, fmt.Errorf("oidc token_url missing")
	}
	values := url.Values{"grant_type": {"authorization_code"}, "client_id": {config.ClientID}, "client_secret": {config.ClientSecret}, "code": {strings.TrimSpace(code)}, "redirect_uri": {config.RedirectURL}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parsed, err := executeJSON(req, "oidc token")
	if err != nil {
		return "", nil, err
	}
	if providerError := FirstNonEmptyString(parsed, "error", "error_description"); providerError != "" {
		return "", nil, fmt.Errorf("oidc token error %s", providerError)
	}
	token := FirstNonEmptyString(parsed, "access_token", "token")
	if token == "" {
		return "", nil, fmt.Errorf("oidc token missing access_token")
	}
	return token, claimsFromMap(parsed), nil
}

func fetchGenericUserInfo(ctx context.Context, token, provider string, config authmodel.AuthProviderConfig, tokenClaims map[string]string) (authmodel.AuthExternalIdentityAssertion, error) {
	if config.UserInfoURL == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("oidc userinfo_url missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.UserInfoURL, nil)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	parsed, err := executeJSON(req, "oidc userinfo")
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	claims := claimsFromMap(parsed)
	for key, value := range tokenClaims {
		if claims[key] == "" && strings.TrimSpace(value) != "" {
			claims[key] = value
		}
	}
	if config.Issuer != "" {
		claims["issuer"] = config.Issuer
	}
	return authmodel.AuthExternalIdentityAssertion{Provider: strings.ToLower(strings.TrimSpace(provider)), Subject: FirstNonEmptyClaim(claims, "sub", "id", "user_id", "open_id", "union_id", "account_id", "login"), Email: FirstNonEmptyClaim(claims, "email", "mail", "emailaddress"), DisplayName: FirstNonEmptyClaim(claims, "name", "display_name", "displayname", "login", "preferred_username"), AvatarURL: FirstNonEmptyClaim(claims, "picture", "avatar_url", "avatar", "avatarUrl"), Claims: claims, Metadata: `{"source":"generic_oidc_userinfo"}`}, nil
}

func exchangeFeishuToken(ctx context.Context, code string, config authmodel.AuthProviderConfig) (string, error) {
	payload, _ := json.Marshal(map[string]string{"grant_type": "authorization_code", "client_id": config.ClientID, "client_secret": config.ClientSecret, "code": strings.TrimSpace(code), "redirect_uri": config.RedirectURL})
	tokenURL := config.TokenURL
	if tokenURL == "" {
		tokenURL = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	parsed, err := executeJSON(req, "feishu token")
	if err != nil {
		return "", err
	}
	if codeValue := stringFromAny(parsed["code"]); codeValue != "" && codeValue != "0" {
		return "", fmt.Errorf("feishu token code %s", codeValue)
	}
	data, _ := parsed["data"].(map[string]any)
	for _, key := range []string{"access_token", "user_access_token"} {
		if token := strings.TrimSpace(stringFromAny(data[key])); token != "" {
			return token, nil
		}
		if token := strings.TrimSpace(stringFromAny(parsed[key])); token != "" {
			return token, nil
		}
	}
	return "", fmt.Errorf("feishu token missing access_token")
}

func fetchFeishuUserInfo(ctx context.Context, token string, config authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error) {
	endpoint := config.UserInfoURL
	if endpoint == "" {
		endpoint = "https://open.feishu.cn/open-apis/authen/v1/user_info"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	parsed, err := executeJSON(req, "feishu user_info")
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	if codeValue := stringFromAny(parsed["code"]); codeValue != "" && codeValue != "0" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("feishu user_info code %s", codeValue)
	}
	data, _ := parsed["data"].(map[string]any)
	if len(data) == 0 {
		data = parsed
	}
	claims := claimsFromMap(data)
	return authmodel.AuthExternalIdentityAssertion{Subject: FirstNonEmptyString(data, "union_id", "open_id", "user_id", "employee_id", "sub", "id"), Email: FirstNonEmptyString(data, "email", "enterprise_email"), DisplayName: FirstNonEmptyString(data, "name", "en_name", "display_name"), AvatarURL: FirstNonEmptyString(data, "avatar_url", "avatar_big", "avatar_middle", "avatar_thumb"), Claims: claims, Metadata: `{"source":"feishu_user_info"}`}, nil
}

func executeJSON(req *http.Request, label string) (map[string]any, error) {
	resp, err := callbackHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s status %d", label, resp.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var parsed map[string]any
	if err := decoder.Decode(&parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func claimsFromMap(values map[string]any) map[string]string {
	claims := map[string]string{}
	for key, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(key))
		text := stringFromAny(value)
		if normalized != "" && text != "" {
			claims[normalized] = text
		}
	}
	if email := strings.ToLower(strings.TrimSpace(FirstNonEmptyClaim(claims, "email", "mail", "emailaddress"))); email != "" {
		if at := strings.LastIndex(email, "@"); at >= 0 && at < len(email)-1 {
			claims["email_domain"] = email[at+1:]
		}
	}
	return claims
}
