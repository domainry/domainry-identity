package identity

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) listAuthRefreshTokensForUser(userID string) ([]identitymodel.AuthRefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []identitymodel.AuthRefreshToken{}
	for _, token := range s.refreshTokens {
		if token.UserID == userID {
			out = append(out, token)
		}
	}
	return out, nil
}

func (s *MemoryIdentityStore) revokeAuthRefreshTokensForUser(userID string, revokedAt string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for hash, token := range s.refreshTokens {
		if token.UserID != userID || token.RevokedAt != "" {
			continue
		}
		token.RevokedAt = revokedAt
		token.LastUsedAt = revokedAt
		s.refreshTokens[hash] = token
		count++
	}
	return count, nil
}
