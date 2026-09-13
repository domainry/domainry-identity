package runtimeactionusage

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

const serviceTokenRefreshWindow = 30 * time.Second

// ApplicationServiceTokenIssuer is the narrow trusted in-process boundary
// used by standalone Identity. Remote callers still exchange credentials
// through Identity's authenticated application-service HTTP endpoint.
type ApplicationServiceTokenIssuer interface {
	IssueApplicationServiceToken(context.Context, identitysdk.ExchangeApplicationServiceTokenRequest, string) (identitysdk.ApplicationServiceToken, error)
}

type ServiceTokenOptions struct {
	Application  identitysdk.ApplicationRef
	Audience     identitysdk.ApplicationKey
	Grant        identitysdk.ApplicationServiceGrant
	CredentialID string
	Now          func() time.Time
}

type ApplicationServiceTokenSource struct {
	issuer  ApplicationServiceTokenIssuer
	options ServiceTokenOptions
	mu      sync.Mutex
	token   string
	expires time.Time
}

func NewApplicationServiceTokenSource(issuer ApplicationServiceTokenIssuer, options ServiceTokenOptions) (*ApplicationServiceTokenSource, error) {
	if issuer == nil || !options.Application.WorkspaceID.Valid() || !options.Application.ApplicationKey.Valid() ||
		!options.Audience.Valid() || !options.Grant.Valid() || strings.TrimSpace(options.CredentialID) == "" {
		return nil, fmt.Errorf("Runtime Action usage service identity is invalid")
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	options.CredentialID = strings.TrimSpace(options.CredentialID)
	return &ApplicationServiceTokenSource{issuer: issuer, options: options}, nil
}

func (source *ApplicationServiceTokenSource) AccessToken(ctx context.Context) (string, error) {
	if source == nil || source.issuer == nil || ctx == nil {
		return "", fmt.Errorf("Runtime Action usage service token source is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	now := source.options.Now().UTC()
	if source.token != "" && now.Add(serviceTokenRefreshWindow).Before(source.expires) {
		return source.token, nil
	}
	request := identitysdk.ExchangeApplicationServiceTokenRequest{
		Application: source.options.Application, Audience: source.options.Audience,
		Grants: []identitysdk.ApplicationServiceGrant{source.options.Grant},
	}
	token, err := source.issuer.IssueApplicationServiceToken(ctx, request, source.options.CredentialID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(token.AccessToken) == "" || !strings.EqualFold(strings.TrimSpace(token.TokenType), "Bearer") ||
		token.Application != source.options.Application || token.Audience != source.options.Audience || token.CredentialID != source.options.CredentialID ||
		len(token.Grants) != 1 || token.Grants[0] != source.options.Grant || !token.ExpiresAt.After(now.Add(serviceTokenRefreshWindow)) {
		return "", fmt.Errorf("Identity returned an invalid Runtime Action usage service token")
	}
	source.token, source.expires = strings.TrimSpace(token.AccessToken), token.ExpiresAt.UTC()
	return source.token, nil
}

var _ TokenSource = (*ApplicationServiceTokenSource)(nil)
