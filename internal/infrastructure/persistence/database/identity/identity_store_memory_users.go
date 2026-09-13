package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) ListIdentityUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	return s.ListIdentityUsersWithinDataScope(ctx, workspaceID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *MemoryIdentityStore) ListIdentityUsersWithinDataScope(ctx context.Context, workspaceID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUser, error) {
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
		if !identityUserMatchesDataScope(value, scope) {
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
	return s.GetIdentityUserWithinDataScope(ctx, workspaceID, userID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *MemoryIdentityStore) GetIdentityUserWithinDataScope(ctx context.Context, workspaceID, userID string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityUser, bool, error) {
	key, err := identityWorkspaceKey(workspaceID, userID)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[key]
	if ok && !identityUserMatchesDataScope(user, scope) {
		return identitymodel.IdentityUser{}, false, nil
	}
	return cloneIdentityUser(user), ok, nil
}

func identityUserMatchesDataScope(user identitymodel.IdentityUser, scope identitymodel.IdentityDataScopeFilter) bool {
	scope = scope.Normalized()
	if scope.Unrestricted {
		return true
	}
	for _, userID := range scope.OwnerUserIDs {
		if user.ID == userID {
			return true
		}
	}
	for _, orgID := range scope.OwnerOrgIDs {
		if user.OrgID == orgID {
			return true
		}
	}
	return false
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
		if existing.Status == "erased" {
			return fmt.Errorf("identity subject is erased")
		}
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

func (s *MemoryIdentityStore) CreateIdentityUser(_ context.Context, workspaceID string, user identitymodel.IdentityUser) error {
	key, err := identityWorkspaceKey(workspaceID, user.ID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(user.ID) == "" {
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
	if _, exists := s.users[key]; exists {
		return fmt.Errorf("identity user %q already exists", user.ID)
	}
	now := nowString()
	user.Version, user.CreatedAt, user.UpdatedAt = 1, now, now
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
	if !ok || user.Status == "erased" || user.Version != expectedVersion {
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
	for _, user := range users {
		if existing, ok := s.users[prefix+user.ID]; ok && existing.Status == "erased" {
			return fmt.Errorf("identity subject is erased")
		}
	}
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
			if existing.Status == "erased" {
				return fmt.Errorf("identity subject is erased")
			}
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

func (s *MemoryIdentityStore) UpdateIdentityUsersWithinDataScopeAtomically(_ context.Context, workspaceID string, users []identitymodel.IdentityUser, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return false, err
	}
	for _, user := range users {
		if strings.TrimSpace(user.ID) == "" {
			return false, fmt.Errorf("user id is required")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, user := range users {
		existing, ok := s.users[prefix+user.ID]
		if !ok || existing.Status == "erased" || !identityUserMatchesDataScope(existing, scope) {
			return false, nil
		}
	}
	now := nowString()
	for _, user := range users {
		existing := s.users[prefix+user.ID]
		if user.Status == "" {
			user.Status = identitymodel.IdentityStatusActive
		}
		if user.AccountType == "" {
			user.AccountType = identitymodel.IdentityAccountHuman
		}
		user.Version = existing.Version + 1
		user.CreatedAt = existing.CreatedAt
		user.UpdatedAt = now
		s.users[prefix+user.ID] = cloneIdentityUser(user)
	}
	return true, nil
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
		if existing.Status == "erased" {
			return fmt.Errorf("identity subject is erased")
		}
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

func (s *MemoryIdentityStore) UpsertIdentityUserWithRoleAssignmentsWithinDataScopeAtomically(
	_ context.Context,
	workspaceID string,
	user identitymodel.IdentityUser,
	assignments []identitymodel.IdentityUserRoleAssignment,
	scope identitymodel.IdentityDataScopeFilter,
) (bool, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return false, err
	}
	if user.ID == "" {
		return false, fmt.Errorf("user id is required")
	}
	for _, assignment := range assignments {
		if assignment.UserID != user.ID || assignment.RoleID == "" {
			return false, fmt.Errorf("user id and role id are required")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := prefix + user.ID
	existing, found := s.users[key]
	if !found || existing.Status == "erased" || !identityUserMatchesDataScope(existing, scope) {
		return false, nil
	}
	if user.Status == "" {
		user.Status = identitymodel.IdentityStatusActive
	}
	if user.AccountType == "" {
		user.AccountType = identitymodel.IdentityAccountHuman
	}
	now := nowString()
	user.Version, user.CreatedAt, user.UpdatedAt = existing.Version+1, existing.CreatedAt, now
	for assignmentKey, assignment := range s.userRoles {
		if strings.HasPrefix(assignmentKey, prefix) && assignment.UserID == user.ID {
			delete(s.userRoles, assignmentKey)
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
	s.users[key] = cloneIdentityUser(user)
	return true, nil
}

func cloneIdentityUser(user identitymodel.IdentityUser) identitymodel.IdentityUser {
	return user
}

func (s *MemoryIdentityStore) RemoveIdentityUser(ctx context.Context, workspaceID, userID string) error {
	removed, err := s.RemoveIdentityUserWithinDataScope(ctx, workspaceID, userID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("identity user %q not found", userID)
	}
	return nil
}

func (s *MemoryIdentityStore) RemoveIdentityUserWithinDataScope(_ context.Context, workspaceID, userID string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	key, err := identityWorkspaceKey(workspaceID, userID)
	if err != nil {
		return false, err
	}
	prefix, _ := identityWorkspacePrefix(workspaceID)
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[key]
	if !ok || user.Status == "erased" || !identityUserMatchesDataScope(user, scope) {
		return false, nil
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
	return true, nil
}

func (s *MemoryIdentityStore) SetIdentityUserStatus(ctx context.Context, workspaceID, userID string, status identitymodel.IdentityStatus) error {
	updated, err := s.SetIdentityUserStatusWithinDataScope(ctx, workspaceID, userID, status, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
	if err != nil {
		return err
	}
	if !updated {
		return fmt.Errorf("identity user %q not found", userID)
	}
	return nil
}

func (s *MemoryIdentityStore) SetIdentityUserStatusWithinDataScope(_ context.Context, workspaceID, userID string, status identitymodel.IdentityStatus, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	key, err := identityWorkspaceKey(workspaceID, userID)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[key]
	if !ok || user.Status == "erased" || !identityUserMatchesDataScope(user, scope) {
		return false, nil
	}
	user.Status = status
	user.Version++
	user.UpdatedAt = nowString()
	s.users[key] = user
	return true, nil
}
