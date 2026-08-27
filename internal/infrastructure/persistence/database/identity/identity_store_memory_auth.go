package identity

import (
	"fmt"
	"sort"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) getIdentityCredential(userID string) (identitymodel.IdentityCredential, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	credential, ok := s.credentials[userID]
	return credential, ok, nil
}

func (s *MemoryIdentityStore) upsertIdentityCredential(credential identitymodel.IdentityCredential) error {
	if credential.UserID == "" {
		return fmt.Errorf("credential user id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[credential.UserID] = credential
	return nil
}

func (s *MemoryIdentityStore) recordIdentityLoginFailure(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential := s.credentials[userID]
	credential.UserID = userID
	credential.FailedLoginCount++
	s.credentials[userID] = credential
	return nil
}

func (s *MemoryIdentityStore) recordIdentityLoginSuccess(userID string, at string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential := s.credentials[userID]
	credential.UserID = userID
	credential.FailedLoginCount = 0
	credential.LockedUntil = ""
	credential.LastLoginAt = at
	s.credentials[userID] = credential
	return nil
}

func (s *MemoryIdentityStore) createAuthRefreshToken(token identitymodel.AuthRefreshToken) error {
	if token.ID == "" || token.TokenHash == "" || token.UserID == "" {
		return fmt.Errorf("refresh token id, hash, and user id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token.TokenHash] = token
	return nil
}

func (s *MemoryIdentityStore) getAuthRefreshTokenByHash(tokenHash string) (identitymodel.AuthRefreshToken, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, ok := s.refreshTokens[tokenHash]
	return token, ok, nil
}

func (s *MemoryIdentityStore) revokeAuthRefreshToken(tokenID string, revokedAt string, replacedByID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, token := range s.refreshTokens {
		if token.ID != tokenID {
			continue
		}
		token.RevokedAt = revokedAt
		token.ReplacedByID = replacedByID
		token.LastUsedAt = revokedAt
		s.refreshTokens[hash] = token
		return nil
	}
	return nil
}

func (s *MemoryIdentityStore) listIdentityExternalAccounts(userID string) ([]identitymodel.IdentityExternalAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []identitymodel.IdentityExternalAccount{}
	for _, account := range s.externalAccounts {
		if userID == "" || account.UserID == userID {
			out = append(out, account)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider == out[j].Provider {
			return out[i].ProviderSubject < out[j].ProviderSubject
		}
		return out[i].Provider < out[j].Provider
	})
	return out, nil
}

func (s *MemoryIdentityStore) upsertIdentityExternalAccount(account identitymodel.IdentityExternalAccount) error {
	if account.ID == "" || account.UserID == "" || account.Provider == "" || account.ProviderSubject == "" {
		return fmt.Errorf("external account id, user id, provider, and subject are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.externalAccounts[account.ID] = account
	return nil
}
func (s *MemoryIdentityStore) removeIdentityExternalAccount(accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.externalAccounts, accountID)
	return nil
}
