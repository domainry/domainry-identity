package policy

import (
	"crypto/sha256"
	"encoding/hex"
)

type IdentitySubjectErasure struct {
	Token string
	Name  string
	Email string
}

func IdentityAnonymizedSubject(workspaceID, userID string) IdentitySubjectErasure {
	digest := sha256.Sum256([]byte(workspaceID + "\x00" + userID))
	token := hex.EncodeToString(digest[:12])
	return IdentitySubjectErasure{Token: token, Name: "Erased subject " + token, Email: "erased+" + token + "@invalid.local"}
}
