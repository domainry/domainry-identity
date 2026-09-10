package metadata

import (
	"crypto/sha256"
	"encoding/hex"
)

// Each publication needs a distinct refresh even when its content matches an
// older version. Binding the version also prevents late completion of A from
// completing a later A → B → A publication.
func metadataDefinitionRefreshIntentID(resourceType, resourceKey, schemaVersion, schemaHash string) string {
	sum := sha256.Sum256([]byte(resourceType + "\x00" + resourceKey + "\x00" + schemaVersion + "\x00" + schemaHash))
	return "metadata_refresh:" + hex.EncodeToString(sum[:])[:24]
}
