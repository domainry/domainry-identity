package remotesdk

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

// BrowserApplicationRegistry authenticates a SaaS backend before returning a
// refresh credential. It is application-scoped but intentionally not
// Workspace-scoped: the verified user session selects the Workspace.
type BrowserApplicationRegistry struct {
	digests          map[identitysdk.ApplicationKey][sha256.Size]byte
	permissionOwners map[identitysdk.ApplicationKey]map[string]struct{}
}

func NewBrowserApplicationRegistry(applications map[string][]string, credentials map[string]string, permissionOwnerSets ...map[string][]string) (*BrowserApplicationRegistry, error) {
	registry := &BrowserApplicationRegistry{
		digests: map[identitysdk.ApplicationKey][sha256.Size]byte{}, permissionOwners: map[identitysdk.ApplicationKey]map[string]struct{}{},
	}
	permissionOwners := map[string][]string{}
	if len(permissionOwnerSets) > 0 && permissionOwnerSets[0] != nil {
		permissionOwners = permissionOwnerSets[0]
	}
	for rawApplication := range applications {
		application := identitysdk.ApplicationKey(strings.TrimSpace(rawApplication))
		credential := strings.TrimSpace(credentials[rawApplication])
		if !application.Valid() || credential == "" {
			return nil, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.browser_application_configuration_invalid"}
		}
		registry.digests[application] = sha256.Sum256([]byte(credential))
		registry.permissionOwners[application] = map[string]struct{}{}
		for _, owner := range permissionOwners[rawApplication] {
			owner = strings.TrimSpace(owner)
			if _, err := identitysdk.PermissionSnapshotHash(owner, nil); err != nil {
				return nil, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.browser_application_configuration_invalid"}
			}
			registry.permissionOwners[application][owner] = struct{}{}
		}
	}
	return registry, nil
}

func (registry *BrowserApplicationRegistry) AuthorizeSourceOwner(authorization string, application identitysdk.ApplicationKey, sourceOwner string) bool {
	if !registry.Authorize(authorization, application) {
		return false
	}
	_, allowed := registry.permissionOwners[application][strings.TrimSpace(sourceOwner)]
	return allowed
}

func (registry *BrowserApplicationRegistry) Authorize(authorization string, application identitysdk.ApplicationKey) bool {
	if registry == nil || !application.Valid() {
		return false
	}
	expected, found := registry.digests[application]
	credential := sdkBearerToken(authorization)
	if !found || credential == "" {
		return false
	}
	actual := sha256.Sum256([]byte(credential))
	return subtle.ConstantTimeCompare(expected[:], actual[:]) == 1
}
