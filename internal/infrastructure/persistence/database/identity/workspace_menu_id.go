package identity

import (
	"github.com/domainry/domainry-foundation/entityid"
)

// WorkspaceMenuID materializes one stable tenant-owned menu identity from the
// source-owned menu key. The Workspace participates in the digest because the
// current Identity schema uses a globally unique technical id.
func WorkspaceMenuID(workspaceID, menuKey string) string {
	value, err := entityid.Derive("menu", "identity.workspace-menu", workspaceID, menuKey)
	if err != nil {
		return ""
	}
	return value
}
