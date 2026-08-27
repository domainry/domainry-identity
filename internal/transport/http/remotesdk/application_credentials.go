package remotesdk

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

// ApplicationCredentialRegistry authenticates one Runtime application within
// one tenant and workspace. A credential is never a global Identity service
// password: changing the request scope cannot expand the credential's access.
type ApplicationCredentialRegistry struct {
	credentials []applicationCredential
	clock       func() time.Time
}

type applicationCredential struct {
	credentialID   string
	tenantID       identitysdk.TenantID
	workspaceID    identitysdk.WorkspaceID
	applicationKey identitysdk.ApplicationKey
	digest         [sha256.Size]byte
	limiter        *applicationRateLimiter
}

type ApplicationCredentialDecision struct {
	Authenticated bool
	RateLimited   bool
	Remaining     int
	ResetAt       time.Time
}

// NewApplicationCredentialRegistry builds a registry from configuration keys
// formatted as tenant/workspace/application#credential-id. The
// workspace/application short form means tenant equals workspace, and an
// omitted credential ID means "default". Each path segment is URL
// path-escaped so identifiers containing '/' remain unambiguous. Multiple IDs
// for the same scope support overlap during credential rotation.
func NewApplicationCredentialRegistry(values map[string]string, requestsPerMinute int) (*ApplicationCredentialRegistry, error) {
	if requestsPerMinute <= 0 {
		return nil, fmt.Errorf("Identity application rate limit must be greater than zero")
	}
	registry := &ApplicationCredentialRegistry{credentials: make([]applicationCredential, 0, len(values)), clock: func() time.Time { return time.Now().UTC() }}
	seenDigests := map[[sha256.Size]byte]string{}
	limiters := map[string]*applicationRateLimiter{}
	configuredScopes := make([]string, 0, len(values))
	for configuredScope := range values {
		configuredScopes = append(configuredScopes, configuredScope)
	}
	sort.Strings(configuredScopes)
	for _, configuredScope := range configuredScopes {
		rawCredential := values[configuredScope]
		credentialID, tenantID, workspaceID, applicationKey, err := parseApplicationCredentialScope(configuredScope)
		if err != nil {
			return nil, err
		}
		credential := strings.TrimSpace(rawCredential)
		if credential == "" {
			return nil, fmt.Errorf("Identity application service credential for %s is empty", configuredScope)
		}
		digest := sha256.Sum256([]byte(credential))
		if previousScope, duplicate := seenDigests[digest]; duplicate {
			return nil, fmt.Errorf("Identity application service credential is reused by %s and %s", previousScope, configuredScope)
		}
		seenDigests[digest] = configuredScope
		scopeKey := string(tenantID) + "\x00" + string(workspaceID) + "\x00" + string(applicationKey)
		limiter := limiters[scopeKey]
		if limiter == nil {
			limiter = newApplicationRateLimiter(requestsPerMinute)
			limiters[scopeKey] = limiter
		}
		registry.credentials = append(registry.credentials, applicationCredential{
			credentialID: credentialID, tenantID: tenantID, workspaceID: workspaceID, applicationKey: applicationKey, digest: digest,
			limiter: limiter,
		})
	}
	return registry, nil
}

func (registry *ApplicationCredentialRegistry) Authorize(authorization string, scope identitysdk.ApplicationScope) ApplicationCredentialDecision {
	credential := sdkBearerToken(authorization)
	if registry == nil || credential == "" || !scope.WorkspaceID.Valid() || !scope.ApplicationKey.Valid() {
		return ApplicationCredentialDecision{}
	}
	tenantID := scope.TenantID
	if !tenantID.Valid() {
		tenantID = identitysdk.TenantID(scope.WorkspaceID)
	}
	digest := sha256.Sum256([]byte(credential))
	for _, registered := range registry.credentials {
		tokenMatches := subtle.ConstantTimeCompare(digest[:], registered.digest[:]) == 1
		if tokenMatches && registered.tenantID == tenantID && registered.workspaceID == scope.WorkspaceID && registered.applicationKey == scope.ApplicationKey {
			allowed, remaining, resetAt := registered.limiter.Allow(registry.clock())
			return ApplicationCredentialDecision{Authenticated: true, RateLimited: !allowed, Remaining: remaining, ResetAt: resetAt}
		}
	}
	return ApplicationCredentialDecision{}
}

type applicationRateLimiter struct {
	mu        sync.Mutex
	limit     int
	used      int
	windowEnd time.Time
}

func newApplicationRateLimiter(limit int) *applicationRateLimiter {
	return &applicationRateLimiter{limit: limit}
}

func (limiter *applicationRateLimiter) Allow(now time.Time) (bool, int, time.Time) {
	now = now.UTC()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.windowEnd.IsZero() || !now.Before(limiter.windowEnd) || now.Before(limiter.windowEnd.Add(-time.Minute)) {
		limiter.used = 0
		limiter.windowEnd = now.Truncate(time.Minute).Add(time.Minute)
	}
	if limiter.used >= limiter.limit {
		return false, 0, limiter.windowEnd
	}
	limiter.used++
	return true, limiter.limit - limiter.used, limiter.windowEnd
}

func parseApplicationCredentialScope(value string) (string, identitysdk.TenantID, identitysdk.WorkspaceID, identitysdk.ApplicationKey, error) {
	scopeValue, credentialID, hasCredentialID := strings.Cut(strings.TrimSpace(value), "#")
	if !hasCredentialID {
		credentialID = "default"
	}
	credentialID, err := url.PathUnescape(credentialID)
	if err != nil || identitysdk.ValidateIdentifier("credential_id", credentialID) != nil {
		return "", "", "", "", fmt.Errorf("Identity application service credential scope %q contains an invalid credential ID", value)
	}
	rawParts := strings.Split(scopeValue, "/")
	if len(rawParts) != 2 && len(rawParts) != 3 {
		return "", "", "", "", fmt.Errorf("Identity application service credential scope %q must be workspace/application or tenant/workspace/application", value)
	}
	parts := make([]string, len(rawParts))
	for index, rawPart := range rawParts {
		part, err := url.PathUnescape(rawPart)
		if err != nil || strings.TrimSpace(part) == "" {
			return "", "", "", "", fmt.Errorf("Identity application service credential scope %q contains an invalid escaped identifier", value)
		}
		parts[index] = part
	}
	if len(parts) == 2 {
		parts = []string{parts[0], parts[0], parts[1]}
	}
	tenantID, workspaceID, applicationKey := identitysdk.TenantID(parts[0]), identitysdk.WorkspaceID(parts[1]), identitysdk.ApplicationKey(parts[2])
	if !tenantID.Valid() || !workspaceID.Valid() || !applicationKey.Valid() {
		return "", "", "", "", fmt.Errorf("Identity application service credential scope %q contains an invalid identifier", value)
	}
	return credentialID, tenantID, workspaceID, applicationKey, nil
}

func applicationScope(application identitysdk.ApplicationRef) identitysdk.ApplicationScope {
	return identitysdk.ApplicationScope{
		TenantID: application.TenantID, WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey,
	}
}
