package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func workspaceRoleID(workspaceID, roleKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(workspaceID) + "\x00role\x00" + strings.TrimSpace(roleKey)))
	return "role_" + hex.EncodeToString(sum[:12])
}

// WorkspaceRoleID exposes the stable Identity-owned materialized role ID to
// the embedded module adapter without leaking the hashing convention.
func WorkspaceRoleID(workspaceID, roleKey string) string {
	return workspaceRoleID(workspaceID, roleKey)
}
