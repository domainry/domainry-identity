package identitymodel

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// IdentityLoginNameKey provides a collation-independent, globally unique key
// for the user table's email login. Empty non-login accounts use SQL NULL.
func IdentityLoginNameKey(login string) any {
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(login))
	return hex.EncodeToString(sum[:])
}
