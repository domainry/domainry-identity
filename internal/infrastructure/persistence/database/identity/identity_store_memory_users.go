package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) ListIdentityUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]identitymodel.IdentityUser, 0, len(s.users))
	for key, value := range s.users {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		out = append(out, cloneIdentityUser(value))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryIdentityStore) ListIdentityProfileBindingsByUser(_ context.Context, workspaceID, _ string) ([]identitymodel.IdentityProfileBinding, error) {
	if _, err := identityWorkspacePrefix(workspaceID); err != nil {
		return nil, err
	}
	return []identitymodel.IdentityProfileBinding{}, nil
}

func (s *MemoryIdentityStore) GetIdentityUser(ctx context.Context, workspaceID, userID string) (identitymodel.IdentityUser, bool, error) {
	key, err := identityWorkspaceKey(workspaceID, userID)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[key]
	return cloneIdentityUser(user), ok, nil
}

func (s *MemoryIdentityStore) UpsertIdentityUser(ctx context.Context, workspaceID string, user identitymodel.IdentityUser) error {
	key, err := identityWorkspaceKey(workspaceID, user.ID)
	if err != nil {
		return err
	}
	if user.ID == "" {
		return fmt.Errorf("user id is required")
	}
	if user.Status == "" {
		user.Status = identitymodel.IdentityStatusActive
	}
	if user.AccountType == "" {
		user.AccountType = identitymodel.IdentityAccountHuman
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowString()
	if existing, ok := s.users[key]; ok {
		user.Version = existing.Version + 1
		user.CreatedAt = existing.CreatedAt
	} else {
		user.Version = 1
		user.CreatedAt = now
	}
	user.UpdatedAt = now
	s.users[key] = cloneIdentityUser(user)
	return nil
}

func (s *MemoryIdentityStore) UpdateIdentityUserLocale(_ context.Context, workspaceID, userID, locale string, expectedVersion int64) (identitymodel.IdentityUser, bool, error) {
	key, err := identityWorkspaceKey(workspaceID, userID)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[key]
	if !ok || user.Version != expectedVersion {
		return identitymodel.IdentityUser{}, false, nil
	}
	user.Locale = locale
	user.Version++
	s.users[key] = cloneIdentityUser(user)
	return cloneIdentityUser(user), true, nil
}

func (s *MemoryIdentityStore) UpsertIdentityUsersAtomically(ctx context.Context, workspaceID string, users []identitymodel.IdentityUser) error {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return err
	}
	for _, user := range users {
		if user.ID == "" {
			return fmt.Errorf("user id is required")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowString()
	for _, user := range users {
		if user.Status == "" {
			user.Status = identitymodel.IdentityStatusActive
		}
		if user.AccountType == "" {
			user.AccountType = identitymodel.IdentityAccountHuman
		}
		key := prefix + user.ID
		if existing, ok := s.users[key]; ok {
			user.Version = existing.Version + 1
			user.CreatedAt = existing.CreatedAt
		} else {
			user.Version = 1
			user.CreatedAt = now
		}
		user.UpdatedAt = now
		s.users[key] = cloneIdentityUser(user)
	}
	return nil
}

func (s *MemoryIdentityStore) UpsertIdentityUserWithRoleAssignmentsAtomically(
	_ context.Context,
	workspaceID string,
	user identitymodel.IdentityUser,
	assignments []identitymodel.IdentityUserRoleAssignment,
) error {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return err
	}
	if user.ID == "" {
		return fmt.Errorf("user id is required")
	}
	for _, assignment := range assignments {
		if assignment.UserID != user.ID || assignment.RoleID == "" {
			return fmt.Errorf("user id and role id are required")
		}
	}
	if user.Status == "" {
		user.Status = identitymodel.IdentityStatusActive
	}
	if user.AccountType == "" {
		user.AccountType = identitymodel.IdentityAccountHuman
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowString()
	key := prefix + user.ID
	if existing, ok := s.users[key]; ok {
		user.Version = existing.Version + 1
		user.CreatedAt = existing.CreatedAt
	} else {
		user.Version = 1
		user.CreatedAt = now
	}
	user.UpdatedAt = now
	s.users[key] = cloneIdentityUser(user)
	for key, assignment := range s.userRoles {
		if strings.HasPrefix(key, prefix) && assignment.UserID == user.ID {
			delete(s.userRoles, key)
		}
	}
	for _, assignment := range assignments {
		if assignment.Source == "" {
			assignment.Source = "manual"
		}
		if assignment.Status == "" {
			assignment.Status = "active"
		}
		s.userRoles[prefix+assignment.UserID+"\x00"+assignment.RoleID] = assignment
	}
	return nil
}

func cloneIdentityUser(user identitymodel.IdentityUser) identitymodel.IdentityUser {
	return user
}

func (s *MemoryIdentityStore) RemoveIdentityUser(ctx context.Context, workspaceID, userID string) error {
	key, err := identityWorkspaceKey(workspaceID, userID)
	if err != nil {
		return err
	}
	prefix, _ := identityWorkspacePrefix(workspaceID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[key]; !ok {
		return fmt.Errorf("identity user %q not found", userID)
	}
	delete(s.users, key)
	delete(s.credentials, key)
	for scopedKey, assignment := range s.userRoles {
		if strings.HasPrefix(scopedKey, prefix) && assignment.UserID == userID {
			delete(s.userRoles, scopedKey)
		}
	}
	for accountID, account := range s.externalAccounts {
		if strings.HasPrefix(accountID, prefix) && account.UserID == userID {
			delete(s.externalAccounts, accountID)
		}
	}
	for tokenID, token := range s.refreshTokens {
		if strings.HasPrefix(tokenID, prefix) && token.UserID == userID {
			delete(s.refreshTokens, tokenID)
		}
	}
	return nil
}

func (s *MemoryIdentityStore) SetIdentityUserStatus(ctx context.Context, workspaceID, userID string, status identitymodel.IdentityStatus) error {
	key, err := identityWorkspaceKey(workspaceID, userID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[key]
	if !ok {
		return fmt.Errorf("identity user %q not found", userID)
	}
	user.Status = status
	user.Version++
	user.UpdatedAt = nowString()
	s.users[key] = user
	return nil
}
