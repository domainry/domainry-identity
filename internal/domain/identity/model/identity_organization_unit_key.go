package identitymodel

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
)

// IdentityOrganizationUnitSiblingKey is the database-enforced identity for
// the existing domain invariant that sibling names are unique under
// strings.EqualFold. Parent IDs remain case-sensitive opaque identifiers.
// Hashing keeps the indexed value bounded and gives root nodes a non-NULL
// parent scope on every supported SQL dialect.
func IdentityOrganizationUnitSiblingKey(parentID *string, name string) string {
	parent := ""
	if parentID != nil {
		parent = strings.TrimSpace(*parentID)
	}
	payload := parent + "\x00" + identityEqualFoldKey(strings.TrimSpace(name))
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// identityEqualFoldKey selects one stable rune from each unicode.SimpleFold
// cycle, matching strings.EqualFold without relying on database collation.
func identityEqualFoldKey(value string) string {
	var output strings.Builder
	for _, current := range value {
		canonical := current
		for folded := unicode.SimpleFold(current); folded != current; folded = unicode.SimpleFold(folded) {
			if folded < canonical {
				canonical = folded
			}
		}
		output.WriteRune(canonical)
	}
	return output.String()
}
