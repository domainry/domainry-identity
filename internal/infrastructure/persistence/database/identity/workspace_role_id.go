package identity

import (
	"github.com/domainry/domainry-foundation/entityid"
)

func workspaceRoleID(workspaceID, roleKey string) string {
	value, err := entityid.Derive("role", "identity.workspace-role", workspaceID, roleKey)
	if err != nil {
		return ""
	}
	return value
}

// WorkspaceRoleID exposes the stable Identity-owned materialized role ID to
// the embedded module adapter without leaking the hashing convention.
func WorkspaceRoleID(workspaceID, roleKey string) string {
	return workspaceRoleID(workspaceID, roleKey)
}

// GlobalRoleID is stable for one source-owned global role catalog. It never
// includes a Workspace because the row is shared by every tenant.
func GlobalRoleID(sourceOwner, roleKey string) string {
	value, err := entityid.Derive("role", "identity.global-role", sourceOwner, roleKey)
	if err != nil {
		return ""
	}
	return value
}
