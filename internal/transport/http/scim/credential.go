package scimhttp

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type credentialRegistry struct {
	credentials []scopedCredential
}

type scopedCredential struct {
	workspaceID string
	digest      [sha256.Size]byte
}

func newCredentialRegistry(configured map[string]string) (*credentialRegistry, error) {
	registry := &credentialRegistry{credentials: make([]scopedCredential, 0, len(configured))}
	seen := map[[sha256.Size]byte]string{}
	for workspaceID, token := range configured {
		workspace, err := identitymodel.NewWorkspaceID(strings.TrimSpace(workspaceID))
		if err != nil {
			return nil, fmt.Errorf("SCIM bearer token workspace %q is invalid: %w", workspaceID, err)
		}
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("SCIM bearer token for workspace %q is empty", workspaceID)
		}
		digest := sha256.Sum256([]byte(token))
		if previous, duplicate := seen[digest]; duplicate {
			return nil, fmt.Errorf("SCIM bearer token is reused by workspaces %q and %q", previous, workspace.String())
		}
		seen[digest] = workspace.String()
		registry.credentials = append(registry.credentials, scopedCredential{workspaceID: workspace.String(), digest: digest})
	}
	return registry, nil
}

func (registry *credentialRegistry) authorize(header string) (string, bool) {
	scheme, token, found := strings.Cut(strings.TrimSpace(header), " ")
	if registry == nil || !found || !strings.EqualFold(strings.TrimSpace(scheme), "Bearer") || strings.TrimSpace(token) == "" {
		return "", false
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(token)))
	for _, credential := range registry.credentials {
		if subtle.ConstantTimeCompare(digest[:], credential.digest[:]) == 1 {
			return credential.workspaceID, true
		}
	}
	return "", false
}
