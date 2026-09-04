package runtimeactionusage

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

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
)

const (
	queryPath        = "/action/permission-usages/query"
	maxResponseBytes = int64(1 << 20)
)

type Options struct {
	RuntimeURL     string
	RequestTimeout time.Duration
	HTTPClient     *http.Client
	TokenSource    TokenSource
}

type TokenSource interface {
	AccessToken(context.Context) (string, error)
}

// Provider queries the Runtime-owned live Action registry for standalone
// Identity. An authenticated management request is required to initiate the
// query; the cross-service hop uses a separate exact-grant service token. The
// adapter never forwards the browser token or persists the response.
type Provider struct {
	endpoint       *url.URL
	requestTimeout time.Duration
	httpClient     *http.Client
	tokenSource    TokenSource
}

func New(options Options) (*Provider, error) {
	endpoint, err := actionUsageEndpoint(options.RuntimeURL)
	if err != nil {
		return nil, err
	}
	if options.RequestTimeout <= 0 {
		return nil, fmt.Errorf("Runtime Action usage request timeout must be positive")
	}
	if options.TokenSource == nil {
		return nil, fmt.Errorf("Runtime Action usage service token source is required")
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	return &Provider{endpoint: endpoint, requestTimeout: options.RequestTimeout, httpClient: client, tokenSource: options.TokenSource}, nil
}

func (provider *Provider) QueryPermissionUsages(ctx context.Context, request actioncontract.PermissionUsageRequest) (actioncontract.PermissionUsageSnapshot, error) {
	if provider == nil || provider.endpoint == nil || provider.httpClient == nil || provider.tokenSource == nil {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("Runtime Action usage provider is unavailable")
	}
	if ctx == nil {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("Runtime Action usage context is required")
	}
	if err := request.Validate(); err != nil {
		return actioncontract.PermissionUsageSnapshot{}, err
	}
	requestIdentity, ok := identitysdk.RequestIdentityFromContext(ctx)
	if !ok || strings.TrimSpace(requestIdentity.AccessToken) == "" {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("Runtime Action usage query requires the authenticated caller")
	}
	workspaceID := strings.TrimSpace(requestIdentity.Principal.WorkspaceID)
	contextWorkspaceID := requestcontext.WorkspaceID(ctx)
	if workspaceID == "" {
		workspaceID = contextWorkspaceID
	}
	if workspaceID == "" || contextWorkspaceID != "" && contextWorkspaceID != workspaceID {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("Runtime Action usage caller workspace is invalid")
	}
	serviceToken, err := provider.tokenSource.AccessToken(ctx)
	if err != nil {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("acquire Runtime Action usage service token: %w", err)
	}
	serviceToken = strings.TrimSpace(serviceToken)
	if serviceToken == "" {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("Runtime Action usage service token is empty")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("encode Runtime Action usage request: %w", err)
	}
	requestContext, cancel := context.WithTimeout(ctx, provider.requestTimeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(requestContext, http.MethodPost, provider.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("build Runtime Action usage request: %w", err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+serviceToken)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("X-Workspace-ID", workspaceID)
	if requestID := requestcontext.RequestID(ctx); requestID != "" {
		httpRequest.Header.Set("X-Request-ID", requestID)
	}
	response, err := provider.httpClient.Do(httpRequest)
	if err != nil {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("query Runtime Action usages: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("query Runtime Action usages: unexpected HTTP status %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("read Runtime Action usage response: %w", err)
	}
	if int64(len(payload)) > maxResponseBytes {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("Runtime Action usage response exceeds %d bytes", maxResponseBytes)
	}
	var snapshot actioncontract.PermissionUsageSnapshot
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("decode Runtime Action usage response: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("decode Runtime Action usage response: %w", err)
	}
	if err := snapshot.ValidateFor(request); err != nil {
		return actioncontract.PermissionUsageSnapshot{}, fmt.Errorf("validate Runtime Action usage response: %w", err)
	}
	return snapshot, nil
}

func actionUsageEndpoint(rawURL string) (*url.URL, error) {
	baseURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || baseURL == nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("Runtime Action usage URL must be an absolute HTTP(S) URL")
	}
	if !strings.EqualFold(baseURL.Scheme, "http") && !strings.EqualFold(baseURL.Scheme, "https") {
		return nil, fmt.Errorf("Runtime Action usage URL must use HTTP or HTTPS")
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("Runtime Action usage URL must not contain credentials, query, or fragment")
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/") + queryPath
	baseURL.RawPath = ""
	return baseURL, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

var _ actioncontract.PermissionUsageProvider = (*Provider)(nil)
