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
	var revokedAt int64
	var replacedByID sql.NullString
	var lastUsedAt int64
	var methods string
	var authenticationTime, expiresAt, createdAt int64
	err := rows.Scan(&token.ID, &token.UserID, &token.SessionID, &token.Audience, &authenticationTime, &methods, &token.AssuranceLevel, &token.TokenHash, &expiresAt, &revokedAt, &replacedByID, &lastUsedAt, &createdAt)
	if err == nil && json.Unmarshal([]byte(methods), &token.AuthenticationMethods) != nil {
		return identitymodel.AuthRefreshToken{}, fmt.Errorf("decode refresh token authentication methods")
	}
	token.AuthenticationTime = authenticationTime / 1000
	token.ExpiresAt, token.RevokedAt = timeString(expiresAt), timeString(revokedAt)
	token.ReplacedByID = valueFromNull(replacedByID)
	token.LastUsedAt, token.CreatedAt = timeString(lastUsedAt), timeString(createdAt)
	return token, err
}
