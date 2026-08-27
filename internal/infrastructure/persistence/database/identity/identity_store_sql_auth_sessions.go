package identity

import (
	"database/sql"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func scanAuthRefreshToken(rows interface {
	Scan(dest ...any) error
}) (identitymodel.AuthRefreshToken, error) {
	var token identitymodel.AuthRefreshToken
	var revokedAt sql.NullString
	var replacedByID sql.NullString
	var lastUsedAt sql.NullString
	err := rows.Scan(&token.ID, &token.UserID, &token.SessionID, &token.Audience, &token.TokenHash, &token.ExpiresAt, &revokedAt, &replacedByID, &lastUsedAt, &token.CreatedAt)
	token.RevokedAt = valueFromNull(revokedAt)
	token.ReplacedByID = valueFromNull(replacedByID)
	token.LastUsedAt = valueFromNull(lastUsedAt)
	return token, err
}
