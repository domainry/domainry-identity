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
// one workspace. A credential is never a global Identity service
// password: changing the request scope cannot expand the credential's access.
type ApplicationCredentialRegistry struct {
	credentials []applicationCredential
	clock       func() time.Time
}

type applicationCredential struct {
	credentialID     string
	workspaceID      identitysdk.WorkspaceID
	applicationKey   identitysdk.ApplicationKey
	sourceOwners     map[string]struct{}
	serviceAudiences map[string]struct{}
	serviceGrants    map[string]struct{}
	digest           [sha256.Size]byte
	limiter          *applicationRateLimiter
}

type ApplicationCredentialDecision struct {
	Authenticated        bool
	SourceOwnerAllowed   bool
	RateLimited          bool
	Remaining            int
	ResetAt              time.Time
	CredentialID         string
	ServicePolicyAllowed bool
}

// NewApplicationCredentialRegistry builds a registry from configuration keys
// formatted as workspace/application#credential-id. An omitted credential ID
// means "default". Each path segment is URL
// path-escaped so identifiers containing '/' remain unambiguous. Multiple IDs
// for the same scope support overlap during credential rotation.
func NewApplicationCredentialRegistry(values map[string]string, permissionOwners map[string][]string, requestsPerMinute int, configuredServicePolicies ...map[string][]string) (*ApplicationCredentialRegistry, error) {
	if requestsPerMinute <= 0 {
		return nil, fmt.Errorf("Identity application rate limit must be greater than zero")
	}
	registry := &ApplicationCredentialRegistry{credentials: make([]applicationCredential, 0, len(values)), clock: func() time.Time { return time.Now().UTC() }}
	seenDigests := map[[sha256.Size]byte]string{}
	seenCredentialScopes := map[string]string{}
	limiters := map[string]*applicationRateLimiter{}
	applicationScopes := map[string]struct{}{}
	configuredScopes := make([]string, 0, len(values))
	servicePolicies := map[string][]string{}
	if len(configuredServicePolicies) > 0 && configuredServicePolicies[0] != nil {
		servicePolicies = configuredServicePolicies[0]
	}
	for configuredScope := range values {
		configuredScopes = append(configuredScopes, configuredScope)
	}
	sort.Strings(configuredScopes)
	for _, configuredScope := range configuredScopes {
		rawCredential := values[configuredScope]
		credentialID, workspaceID, applicationKey, err := parseApplicationCredentialScope(configuredScope)
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
		scopeKey := string(workspaceID) + "\x00" + string(applicationKey)
		credentialScope := scopeKey + "\x00" + credentialID
		if previous, duplicate := seenCredentialScopes[credentialScope]; duplicate {
			return nil, fmt.Errorf("Identity credential scopes %q and %q identify the same workspace/application/credential", previous, configuredScope)
		}
		seenCredentialScopes[credentialScope] = configuredScope
		applicationScopes[scopeKey] = struct{}{}
		owners, err := applicationPermissionOwners(permissionOwners, workspaceID, applicationKey)
		if err != nil {
			return nil, err
		}
		audiences, grants, err := applicationServicePolicy(servicePolicies, workspaceID, applicationKey)
		if err != nil {
			return nil, err
		}
		limiter := limiters[scopeKey]
		if limiter == nil {
			limiter = newApplicationRateLimiter(requestsPerMinute)
			limiters[scopeKey] = limiter
		}
		registry.credentials = append(registry.credentials, applicationCredential{
			credentialID: credentialID, workspaceID: workspaceID, applicationKey: applicationKey, digest: digest,
			sourceOwners: owners, serviceAudiences: audiences, serviceGrants: grants, limiter: limiter,
		})
	}
	for configuredScope, owners := range permissionOwners {
		_, workspaceID, applicationKey, err := parseApplicationCredentialScope(configuredScope)
		if err != nil {
			return nil, fmt.Errorf("invalid Identity application permission owner scope: %w", err)
		}
		scopeKey := string(workspaceID) + "\x00" + string(applicationKey)
		if _, registered := applicationScopes[scopeKey]; !registered {
			return nil, fmt.Errorf("Identity application permission owner scope %q has no service credential", configuredScope)
		}
		if len(owners) == 0 {
			return nil, fmt.Errorf("Identity application permission owner scope %q is empty", configuredScope)
		}
	}
	for configuredScope, policy := range servicePolicies {
		_, workspaceID, applicationKey, err := parseApplicationCredentialScope(configuredScope)
		if err != nil {
			return nil, fmt.Errorf("invalid Identity application service policy scope: %w", err)
		}
		scopeKey := string(workspaceID) + "\x00" + string(applicationKey)
		if _, registered := applicationScopes[scopeKey]; !registered {
			return nil, fmt.Errorf("Identity application service policy scope %q has no service credential", configuredScope)
		}
		if len(policy) == 0 {
			return nil, fmt.Errorf("Identity application service policy scope %q is empty", configuredScope)
		}
	}
	return registry, nil
}

func (registry *ApplicationCredentialRegistry) AuthorizeApplicationServiceRequest(authorization string, request identitysdk.ExchangeApplicationServiceTokenRequest) ApplicationCredentialDecision {
	decision := registry.authorize(authorization, applicationScope(request.Application), "", false)
	if !decision.Authenticated || decision.RateLimited {
		return decision
	}
	digest := sha256.Sum256([]byte(sdkBearerToken(authorization)))
	for _, registered := range registry.credentials {
		if subtle.ConstantTimeCompare(digest[:], registered.digest[:]) != 1 || registered.credentialID != decision.CredentialID {
			continue
		}
		if _, allowed := registered.serviceAudiences[string(request.Audience)]; !allowed {
			return decision
		}
		for _, grant := range request.Grants {
			if _, allowed := registered.serviceGrants[string(grant.Resource)+"."+string(grant.Action)]; !allowed {
				return decision
			}
		}
		decision.ServicePolicyAllowed = true
		return decision
	}
	return decision
}

func (registry *ApplicationCredentialRegistry) Authorize(authorization string, scope identitysdk.ApplicationScope) ApplicationCredentialDecision {
	return registry.authorize(authorization, scope, "", false)
}

func (registry *ApplicationCredentialRegistry) AuthorizeSourceOwner(authorization string, scope identitysdk.ApplicationScope, sourceOwner string) ApplicationCredentialDecision {
	return registry.authorize(authorization, scope, strings.TrimSpace(sourceOwner), true)
}

func (registry *ApplicationCredentialRegistry) authorize(authorization string, scope identitysdk.ApplicationScope, sourceOwner string, requireSourceOwner bool) ApplicationCredentialDecision {
	credential := sdkBearerToken(authorization)
	if registry == nil || credential == "" || !scope.WorkspaceID.Valid() || !scope.ApplicationKey.Valid() || requireSourceOwner && sourceOwner == "" {
		return ApplicationCredentialDecision{}
	}
	digest := sha256.Sum256([]byte(credential))
	for _, registered := range registry.credentials {
		tokenMatches := subtle.ConstantTimeCompare(digest[:], registered.digest[:]) == 1
		_, ownerAllowed := registered.sourceOwners[sourceOwner]
		if tokenMatches && registered.workspaceID == scope.WorkspaceID && registered.applicationKey == scope.ApplicationKey {
			allowed, remaining, resetAt := registered.limiter.Allow(registry.clock())
			return ApplicationCredentialDecision{Authenticated: true, SourceOwnerAllowed: !requireSourceOwner || ownerAllowed, RateLimited: !allowed, Remaining: remaining, ResetAt: resetAt, CredentialID: registered.credentialID}
		}
	}
	return ApplicationCredentialDecision{}
}

func applicationPermissionOwners(configured map[string][]string, workspaceID identitysdk.WorkspaceID, applicationKey identitysdk.ApplicationKey) (map[string]struct{}, error) {
	result := map[string]struct{}{}
	for configuredScope, owners := range configured {
		_, configuredWorkspaceID, configuredApplicationKey, err := parseApplicationCredentialScope(configuredScope)
		if err != nil {
			return nil, fmt.Errorf("invalid Identity application permission owner scope: %w", err)
		}
		if configuredWorkspaceID != workspaceID || configuredApplicationKey != applicationKey {
			continue
		}
		for _, owner := range owners {
			owner = strings.TrimSpace(owner)
			if _, err := identitysdk.PermissionSnapshotHash(owner, nil); err != nil {
				return nil, fmt.Errorf("Identity application permission owner %q is invalid: %w", owner, err)
			}
			result[owner] = struct{}{}
		}
	}
	return result, nil
}

func applicationServicePolicy(configured map[string][]string, workspaceID identitysdk.WorkspaceID, applicationKey identitysdk.ApplicationKey) (map[string]struct{}, map[string]struct{}, error) {
	audiences, grants := map[string]struct{}{}, map[string]struct{}{}
	for configuredScope, values := range configured {
		_, configuredWorkspaceID, configuredApplicationKey, err := parseApplicationCredentialScope(configuredScope)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid Identity application service policy scope: %w", err)
		}
		if configuredWorkspaceID != workspaceID || configuredApplicationKey != applicationKey {
			continue
		}
		for _, value := range values {
			kind, item, found := strings.Cut(strings.TrimSpace(value), ":")
			item = strings.TrimSpace(item)
			switch {
			case found && kind == "audience" && identitysdk.ApplicationKey(item).Valid():
				audiences[item] = struct{}{}
			case found && kind == "grant":
				resource, action, valid := strings.Cut(item, ".")
				if !valid || !identitysdk.ResourceType(resource).Valid() || !identitysdk.Action(action).Valid() {
					return nil, nil, fmt.Errorf("Identity application service grant policy %q is invalid", value)
				}
				grants[item] = struct{}{}
			default:
				return nil, nil, fmt.Errorf("Identity application service policy %q must be audience:<application> or grant:<resource>.<action>", value)
			}
		}
	}
	return audiences, grants, nil
}

// Active reports whether a credential rotation ID remains registered for the
// exact application scope. Resource-service verification uses this after JWT
// signature/grant verification so removing an old credential ID revokes its
// outstanding short-lived tokens immediately.
func (registry *ApplicationCredentialRegistry) Active(scope identitysdk.ApplicationScope, credentialID string) bool {
	if registry == nil || !scope.WorkspaceID.Valid() || !scope.ApplicationKey.Valid() || strings.TrimSpace(credentialID) == "" {
		return false
	}
	for _, registered := range registry.credentials {
		if registered.workspaceID == scope.WorkspaceID && registered.applicationKey == scope.ApplicationKey && registered.credentialID == credentialID {
			return true
		}
	}
	return false
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

// parseApplicationCredentialScope accepts workspace/application#credential-id.
func parseApplicationCredentialScope(value string) (string, identitysdk.WorkspaceID, identitysdk.ApplicationKey, error) {
	scopeValue, credentialID, hasCredentialID := strings.Cut(strings.TrimSpace(value), "#")
	if !hasCredentialID {
		credentialID = "default"
	}
	credentialID, err := url.PathUnescape(credentialID)
	if err != nil || identitysdk.ValidateIdentifier("credential_id", credentialID) != nil {
		return "", "", "", fmt.Errorf("Identity application service credential scope %q contains an invalid credential ID", value)
	}
	rawParts := strings.Split(scopeValue, "/")
	if len(rawParts) != 2 {
		return "", "", "", fmt.Errorf("Identity application service credential scope %q must be workspace/application", value)
	}
	parts := make([]string, len(rawParts))
	for index, rawPart := range rawParts {
		part, err := url.PathUnescape(rawPart)
		if err != nil || strings.TrimSpace(part) == "" {
			return "", "", "", fmt.Errorf("Identity application service credential scope %q contains an invalid escaped identifier", value)
		}
		parts[index] = part
	}
	workspaceID, applicationKey := identitysdk.WorkspaceID(parts[0]), identitysdk.ApplicationKey(parts[1])
	if !workspaceID.Valid() || !applicationKey.Valid() {
		return "", "", "", fmt.Errorf("Identity application service credential scope %q contains an invalid identifier", value)
	}
	return credentialID, workspaceID, applicationKey, nil
}

func applicationScope(application identitysdk.ApplicationRef) identitysdk.ApplicationScope {
	return identitysdk.ApplicationScope{
		WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey,
	}
}
