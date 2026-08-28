package identityprovider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

const lineLIFFIDTokenVerifyURL = "https://api.line.me/oauth2/v2.1/verify"

// ExchangeLineLIFFIDToken verifies a LIFF ID token with LINE. Only the
// provider response is projected; client-supplied profile data is never used.
func ExchangeLineLIFFIDToken(ctx context.Context, provider, idToken string, config authmodel.AuthProviderConfig) (authmodel.AuthExternalIdentityAssertion, error) {
	idToken, clientID := strings.TrimSpace(idToken), strings.TrimSpace(config.ClientID)
	if idToken == "" || clientID == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("line LIFF id token and channel id are required")
	}
	endpoint := strings.TrimSpace(config.TokenURL)
	if endpoint == "" {
		endpoint = lineLIFFIDTokenVerifyURL
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.Fragment != "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("line LIFF verify URL is invalid")
	}
	values := url.Values{"id_token": {idToken}, "client_id": {clientID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := executeJSON(req, "line LIFF id token verify")
	if err != nil {
		return authmodel.AuthExternalIdentityAssertion{}, err
	}
	if rejected := FirstNonEmptyString(response, "error", "error_description"); rejected != "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("line LIFF id token rejected: %s", rejected)
	}
	if audience := FirstNonEmptyString(response, "aud"); audience != "" && audience != clientID {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("line LIFF id token audience mismatch")
	}
	subject := FirstNonEmptyString(response, "sub")
	if subject == "" {
		return authmodel.AuthExternalIdentityAssertion{}, fmt.Errorf("line LIFF id token missing subject")
	}
	return authmodel.AuthExternalIdentityAssertion{
		Provider: strings.ToLower(strings.TrimSpace(provider)), Subject: subject, ProviderSubjectVerified: true,
		Email: FirstNonEmptyString(response, "email"), DisplayName: FirstNonEmptyString(response, "name"), AvatarURL: FirstNonEmptyString(response, "picture"),
		Claims: claimsFromMap(response), Metadata: `{"source":"line_liff_id_token_verify"}`,
	}, nil
}
