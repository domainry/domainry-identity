package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// WorkspaceMenuID materializes one stable tenant-owned menu identity from the
// source-owned menu key. The Workspace participates in the digest because the
// current Identity schema uses a globally unique technical id.
func WorkspaceMenuID(workspaceID, menuKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(workspaceID) + "\x00menu\x00" + strings.TrimSpace(menuKey)))
	return "menu_" + hex.EncodeToString(sum[:12])
}
