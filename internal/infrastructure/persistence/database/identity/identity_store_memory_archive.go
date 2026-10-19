package identity

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) ArchiveIdentityAccountWithinDataScope(_ context.Context, workspaceID, userID string, expectedVersion int64, scope identitymodel.IdentityDataScopeFilter) (int, bool, error) {
	key, err := identityWorkspaceKey(workspaceID, userID)
	if err != nil {
		return 0, false, err
	}
	prefix, _ := identityWorkspacePrefix(workspaceID)
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[key]
	if !ok || user.Status == "erased" || !identityUserMatchesDataScope(user, scope) {
		return 0, false, nil
	}
	if user.AccountType != identitymodel.IdentityAccountHuman {
		return 0, false, apperror.New(apperror.KindBadRequest, "backend.identity.user_archive_human_required", nil, nil)
	}
	if user.Status == identitymodel.IdentityStatusDeleted {
		return 0, true, nil
	}
	if expectedVersion > 0 && user.Version != expectedVersion {
		return 0, false, apperror.New(apperror.KindConflict, "backend.identity.user_version_conflict", nil, nil)
	}
	now := nowString()
	user.Status = identitymodel.IdentityStatusDeleted
	user.Version++
	user.UpdatedAt = now
	s.users[key] = user
	delete(s.credentials, key)
	for k, role := range s.userRoles {
		if strings.HasPrefix(k, prefix) && role.UserID == userID && role.Status != "revoked" {
			role.Status = "revoked"
			role.RevokedAt = now
			role.RevokeReason = "account_archived"
			role.UpdatedAt = now
			s.userRoles[k] = role
		}
	}
	revoked := 0
	for k, token := range s.refreshTokens {
		if strings.HasPrefix(k, prefix) && token.UserID == userID && token.RevokedAt == "" {
			token.RevokedAt = now
			token.LastUsedAt = now
			s.refreshTokens[k] = token
			revoked++
		}
	}
	return revoked, true, nil
}
