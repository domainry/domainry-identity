package identityprovider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

const alipayMiniProgramGatewayURL = "https://openapi.alipay.com/gateway.do"

func ExchangeAlipayMiniProgramCode(ctx context.Context, provider, code string, config authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error) {
	code = strings.TrimSpace(code)
	if code == "" || strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" || strings.TrimSpace(config.VerificationKey) == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("alipay mini program code, app id, private key and verification key are required")
	}
	privateKey, err := parseRSAPrivateKey(config.ClientSecret)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("parse alipay application private key: %w", err)
	}
	values := url.Values{
		"app_id": {strings.TrimSpace(config.ClientID)}, "method": {"alipay.system.oauth.token"},
		"format": {"JSON"}, "charset": {"utf-8"}, "sign_type": {"RSA2"},
		"timestamp": {time.Now().In(time.FixedZone("UTC+8", 8*60*60)).Format("2006-01-02 15:04:05")}, "version": {"1.0"},
		"grant_type": {"authorization_code"}, "code": {code},
	}
	signature, err := signAlipayValues(values, privateKey)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("sign alipay token request: %w", err)
	}
	values.Set("sign", signature)
	endpoint := strings.TrimSpace(config.TokenURL)
	if endpoint == "" {
		endpoint = alipayMiniProgramGatewayURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := callbackHTTPClient.Do(req)
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	defer resp.Body.Close()
	var envelope struct {
		Response json.RawMessage `json:"alipay_system_oauth_token_response"`
		Sign     string          `json:"sign"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || decoder.Decode(&envelope) != nil || len(envelope.Response) == 0 {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("alipay token response invalid")
	}
	publicKey, err := parseRSAPublicKey(config.VerificationKey)
	if err != nil || !verifyAlipayResponse(envelope.Response, envelope.Sign, publicKey) {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("alipay token response signature invalid")
	}
	var token struct {
		Code        string `json:"code"`
		Message     string `json:"msg"`
		UserID      string `json:"user_id"`
		OpenID      string `json:"open_id"`
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(envelope.Response, &token) != nil || (token.Code != "" && token.Code != "10000") || strings.TrimSpace(token.AccessToken) == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("alipay token exchange rejected: %s", token.Code)
	}
	subject := strings.TrimSpace(token.UserID)
	if subject == "" {
		subject = strings.TrimSpace(token.OpenID)
	}
	if subject == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("alipay token response missing user identity")
	}
	claims := map[string]string{}
	if token.UserID != "" {
		claims["user_id"] = token.UserID
	}
	if token.OpenID != "" {
		claims["open_id"] = token.OpenID
	}
	return authmodel.AuthExternalIdentityAssertion{Provider: strings.ToLower(strings.TrimSpace(provider)), Subject: subject, Claims: claims, Metadata: `{"source":"alipay_system_oauth_token"}`}, nil
}

func signAlipayValues(values url.Values, privateKey *rsa.PrivateKey) (string, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "sign" && strings.TrimSpace(values.Get(key)) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values.Get(key))
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "&")))
	signed, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	return base64.StdEncoding.EncodeToString(signed), err
}

func verifyAlipayResponse(payload json.RawMessage, encodedSignature string, publicKey *rsa.PublicKey) bool {
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedSignature))
	if err != nil || publicKey == nil {
		return false
	}
	digest := sha256.Sum256(payload)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature) == nil
}

func parseRSAPrivateKey(material string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(material)))
	if block == nil {
		return nil, fmt.Errorf("PEM private key required")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parseRSAPublicKey(material string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(material)))
	if block == nil {
		return nil, fmt.Errorf("PEM public key required")
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return key, nil
		}
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if key, pkcs1Err := x509.ParsePKCS1PublicKey(block.Bytes); pkcs1Err == nil {
			return key, nil
		}
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("RSA public key required")
	}
	return key, nil
}
