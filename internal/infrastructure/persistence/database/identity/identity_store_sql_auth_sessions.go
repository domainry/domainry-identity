package identity

import (
	"database/sql"
	"encoding/json"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func scanAuthRefreshToken(rows interface {
	Scan(dest ...any) error
}) (identitymodel.AuthRefreshToken, error) {
	var token identitymodel.AuthRefreshToken
	var revokedAt sql.NullString
	var replacedByID sql.NullString
	var lastUsedAt sql.NullString
	var methods string
	err := rows.Scan(&token.ID, &token.UserID, &token.SessionID, &token.Audience, &token.AuthenticationTime, &methods, &token.AssuranceLevel, &token.TokenHash, &token.ExpiresAt, &revokedAt, &replacedByID, &lastUsedAt, &token.CreatedAt)
	if err == nil && json.Unmarshal([]byte(methods), &token.AuthenticationMethods) != nil {
		return identitymodel.AuthRefreshToken{}, fmt.Errorf("decode refresh token authentication methods")
	}
	token.RevokedAt = valueFromNull(revokedAt)
	token.ReplacedByID = valueFromNull(replacedByID)
	token.LastUsedAt = valueFromNull(lastUsedAt)
	return token, err
}
