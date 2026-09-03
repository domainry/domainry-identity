package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *MemoryIdentityStore) ListIdentityRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]identitymodel.IdentityRole, 0, len(s.roles))
	for key, value := range s.roles {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		out = append(out, cloneIdentityRole(value))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryIdentityStore) ApplyIdentityRoleRequestDecision(_ context.Context, workspaceID string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, expectedStatus string) error {
	requestKey, err := identityWorkspaceKey(workspaceID, request.ID)
	if err != nil {
		return err
	}
	assignmentKeys := make([]string, len(assignments))
	for index, assignment := range assignments {
		if assignment.UserID == "" || assignment.RoleID == "" {
			return fmt.Errorf("user id and role id are required")
		}
		// requestKey already validated workspaceID; identityWorkspaceKey cannot
		// fail for assignment values after that workspace validation.
		key, _ := identityWorkspaceKey(workspaceID, assignment.UserID, assignment.RoleID)
		assignmentKeys[index] = key
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, found := s.roleRequests[requestKey]
	if !found || current.Status != expectedStatus {
		return &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.role_request_concurrent_decision"}
	}
	for index, assignment := range assignments {
		assignment.Source = strings.TrimSpace(assignment.Source)
		if assignment.Source == "" {
			assignment.Source = "governance_request"
		}
		assignment.Status = strings.TrimSpace(assignment.Status)
		if assignment.Status == "" {
			assignment.Status = "active"
		}
		s.userRoles[assignmentKeys[index]] = assignment
	}
	s.roleRequests[requestKey] = cloneIdentityRoleRequest(request)
	return nil
}

func (s *MemoryIdentityStore) ApplyIdentityRoleRequestDecisionWithinDataScope(_ context.Context, workspaceID string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, expectedStatus string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	requestKey, err := identityWorkspaceKey(workspaceID, request.ID)
	if err != nil {
		return false, err
	}
	assignmentKeys := make([]string, len(assignments))
	for index, assignment := range assignments {
		if assignment.UserID == "" || assignment.RoleID == "" {
			return false, fmt.Errorf("user id and role id are required")
		}
		key, _ := identityWorkspaceKey(workspaceID, assignment.UserID, assignment.RoleID)
		assignmentKeys[index] = key
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, found := s.roleRequests[requestKey]
	if !found {
		return false, nil
	}
	userKey, _ := identityWorkspaceKey(workspaceID, current.UserID)
	target, found := s.users[userKey]
	if !found || !identityUserMatchesDataScope(target, scope) {
		return false, nil
	}
	if current.Status != expectedStatus {
		return false, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.identity.role_request_concurrent_decision"}
	}
	for index, assignment := range assignments {
		assignment.Source = strings.TrimSpace(assignment.Source)
		if assignment.Source == "" {
			assignment.Source = "governance_request"
		}
		assignment.Status = strings.TrimSpace(assignment.Status)
		if assignment.Status == "" {
			assignment.Status = "active"
		}
		s.userRoles[assignmentKeys[index]] = assignment
	}
	s.roleRequests[requestKey] = cloneIdentityRoleRequest(request)
	return true, nil
}

func (s *MemoryIdentityStore) UpsertIdentityRole(ctx context.Context, workspaceID string, role identitymodel.IdentityRole) error {
	key, err := identityWorkspaceKey(workspaceID, role.ID)
	if err != nil {
		return err
	}
	if role.ID == "" {
		return fmt.Errorf("role id is required")
	}
	if role.Status == "" {
		role.Status = identitymodel.IdentityStatusActive
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[key] = cloneIdentityRole(role)
	return nil
}

func (s *MemoryIdentityStore) RemoveIdentityRole(ctx context.Context, workspaceID, roleID string) error {
	key, err := identityWorkspaceKey(workspaceID, roleID)
	if err != nil {
		return err
	}
	prefix, _ := identityWorkspacePrefix(workspaceID)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.roles, key)
	delete(s.roleMenus, key)
	for scopedKey, assignment := range s.userRoles {
		if strings.HasPrefix(scopedKey, prefix) && assignment.RoleID == roleID {
			delete(s.userRoles, scopedKey)
		}
	}
	return nil
}

func (s *MemoryIdentityStore) AssignIdentityUserRole(ctx context.Context, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
	key, err := identityWorkspaceKey(workspaceID, assignment.UserID, assignment.RoleID)
	if err != nil {
		return err
	}
	if assignment.UserID == "" || assignment.RoleID == "" {
		return fmt.Errorf("user id and role id are required")
	}
	assignment.Source = strings.TrimSpace(assignment.Source)
	if assignment.Source == "" {
		assignment.Source = "manual"
	}
	assignment.Status = strings.TrimSpace(assignment.Status)
	if assignment.Status == "" {
		assignment.Status = "active"
	}
	if assignment.ValidUntil == "" && assignment.ExpiresAt != nil {
		assignment.ValidUntil = strings.TrimSpace(*assignment.ExpiresAt)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userRoles[key] = assignment
	return nil
}

func (s *MemoryIdentityStore) AssignIdentityUserRoleWithinDataScope(_ context.Context, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	key, err := identityWorkspaceKey(workspaceID, assignment.UserID, assignment.RoleID)
	if err != nil {
		return false, err
	}
	userKey, _ := identityWorkspaceKey(workspaceID, assignment.UserID)
	if assignment.UserID == "" || assignment.RoleID == "" {
		return false, fmt.Errorf("user id and role id are required")
	}
	assignment.Source = strings.TrimSpace(assignment.Source)
	if assignment.Source == "" {
		assignment.Source = "manual"
	}
	assignment.Status = strings.TrimSpace(assignment.Status)
	if assignment.Status == "" {
		assignment.Status = "active"
	}
	if assignment.ValidUntil == "" && assignment.ExpiresAt != nil {
		assignment.ValidUntil = strings.TrimSpace(*assignment.ExpiresAt)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, found := s.users[userKey]
	if !found || !identityUserMatchesDataScope(user, scope) {
		return false, nil
	}
	s.userRoles[key] = assignment
	return true, nil
}

func (s *MemoryIdentityStore) RemoveIdentityUserRole(ctx context.Context, workspaceID, userID string, roleID string) error {
	key, err := identityWorkspaceKey(workspaceID, userID, roleID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.userRoles, key)
	return nil
}

func (s *MemoryIdentityStore) RemoveIdentityUserRoleWithinDataScope(_ context.Context, workspaceID, userID string, roleID string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	key, err := identityWorkspaceKey(workspaceID, userID, roleID)
	if err != nil {
		return false, err
	}
	userKey, _ := identityWorkspaceKey(workspaceID, userID)
	s.mu.Lock()
	defer s.mu.Unlock()
	user, found := s.users[userKey]
	if !found || !identityUserMatchesDataScope(user, scope) {
		return false, nil
	}
	delete(s.userRoles, key)
	return true, nil
}

func (s *MemoryIdentityStore) ListIdentityUserRoleAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return s.ListIdentityUserRoleAssignmentsWithinDataScope(ctx, workspaceID, userID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *MemoryIdentityStore) ListIdentityUserRoleAssignmentsWithinDataScope(_ context.Context, workspaceID, userID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUserRoleAssignment, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []identitymodel.IdentityUserRoleAssignment{}
	for key, value := range s.userRoles {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if userID != "" && value.UserID != userID {
			continue
		}
		userKey, _ := identityWorkspaceKey(workspaceID, value.UserID)
		user, found := s.users[userKey]
		if !scope.Unrestricted && (!found || !identityUserMatchesDataScope(user, scope)) {
			continue
		}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UserID == out[j].UserID {
			return out[i].RoleID < out[j].RoleID
		}
		return out[i].UserID < out[j].UserID
	})
	return out, nil
}

func (s *MemoryIdentityStore) GetIdentityEntitlementBatchReceipt(_ context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	key, err := identityWorkspaceKey(workspaceID, strings.TrimSpace(idempotencyKey))
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	receipt, found := s.entitlementReceipts[key]
	return receipt, found, nil
}

func (s *MemoryIdentityStore) GetIdentityEntitlementBatchReceiptWithinDataScope(_ context.Context, workspaceID, idempotencyKey string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	key, err := identityWorkspaceKey(workspaceID, strings.TrimSpace(idempotencyKey))
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	receipt, found := s.entitlementReceipts[key]
	if !found {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, nil
	}
	for _, item := range receipt.Items {
		userKey, keyErr := identityWorkspaceKey(workspaceID, item.UserID)
		if keyErr != nil {
			return identitymodel.IdentityEntitlementBatchReceipt{}, false, keyErr
		}
		user, exists := s.users[userKey]
		if !exists || !identityUserMatchesDataScope(user, scope) {
			return identitymodel.IdentityEntitlementBatchReceipt{}, false, nil
		}
	}
	return receipt, true, nil
}

func (s *MemoryIdentityStore) ApplyIdentityEntitlementBatch(_ context.Context, mutation identitymodel.IdentityEntitlementBatchMutation) (identitymodel.IdentityEntitlementBatchReceipt, error) {
	receiptKey, err := identityWorkspaceKey(mutation.WorkspaceID, strings.TrimSpace(mutation.IdempotencyKey))
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	if strings.TrimSpace(mutation.ActorID) == "" || strings.TrimSpace(mutation.IdempotencyKey) == "" || strings.TrimSpace(mutation.RequestFingerprint) == "" ||
		len(mutation.Items) == 0 || len(mutation.Items) != len(mutation.Assignments) {
		return identitymodel.IdentityEntitlementBatchReceipt{}, fmt.Errorf("identity entitlement batch mutation is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if receipt, found := s.entitlementReceipts[receiptKey]; found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityEntitlementBatchReceipt{}, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.idempotency_key_reused"}
		}
		receipt.Replayed = true
		return receipt, nil
	}
	next := make(map[string]identitymodel.IdentityUserRoleAssignment, len(s.userRoles)+len(mutation.Assignments))
	for key, assignment := range s.userRoles {
		next[key] = assignment
	}
	for _, assignment := range mutation.Assignments {
		if assignment.UserID == "" || assignment.RoleID == "" {
			return identitymodel.IdentityEntitlementBatchReceipt{}, fmt.Errorf("user id and role id are required")
		}
		// receiptKey already validated mutation.WorkspaceID.
		key, _ := identityWorkspaceKey(mutation.WorkspaceID, assignment.UserID, assignment.RoleID)
		next[key] = assignment
	}
	receipt := identitymodel.IdentityEntitlementBatchReceipt{
		ID: identityID("identity_entitlement_batch", mutation.WorkspaceID, mutation.IdempotencyKey), WorkspaceID: mutation.WorkspaceID,
		ActorID: mutation.ActorID, IdempotencyKey: mutation.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint,
		Items: mutation.Items, CreatedAt: nowString(),
	}
	s.userRoles = next
	s.entitlementReceipts[receiptKey] = receipt
	return receipt, nil
}

func (s *MemoryIdentityStore) ApplyIdentityEntitlementBatchWithinDataScope(_ context.Context, mutation identitymodel.IdentityEntitlementBatchMutation, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	receiptKey, err := identityWorkspaceKey(mutation.WorkspaceID, strings.TrimSpace(mutation.IdempotencyKey))
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, err
	}
	if strings.TrimSpace(mutation.ActorID) == "" || strings.TrimSpace(mutation.IdempotencyKey) == "" || strings.TrimSpace(mutation.RequestFingerprint) == "" ||
		len(mutation.Items) == 0 || len(mutation.Items) != len(mutation.Assignments) {
		return identitymodel.IdentityEntitlementBatchReceipt{}, false, fmt.Errorf("identity entitlement batch mutation is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if receipt, found := s.entitlementReceipts[receiptKey]; found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityEntitlementBatchReceipt{}, false, &apperror.AppError{Kind: apperror.KindConflict, Code: "backend.idempotency_key_reused"}
		}
		for _, item := range receipt.Items {
			userKey, keyErr := identityWorkspaceKey(mutation.WorkspaceID, item.UserID)
			if keyErr != nil {
				return identitymodel.IdentityEntitlementBatchReceipt{}, false, keyErr
			}
			user, exists := s.users[userKey]
			if !exists || !identityUserMatchesDataScope(user, scope) {
				return identitymodel.IdentityEntitlementBatchReceipt{}, false, nil
			}
		}
		receipt.Replayed = true
		return receipt, true, nil
	}
	next := make(map[string]identitymodel.IdentityUserRoleAssignment, len(s.userRoles)+len(mutation.Assignments))
	for key, assignment := range s.userRoles {
		next[key] = assignment
	}
	for _, assignment := range mutation.Assignments {
		if assignment.UserID == "" || assignment.RoleID == "" {
			return identitymodel.IdentityEntitlementBatchReceipt{}, false, fmt.Errorf("user id and role id are required")
		}
		userKey, keyErr := identityWorkspaceKey(mutation.WorkspaceID, assignment.UserID)
		if keyErr != nil {
			return identitymodel.IdentityEntitlementBatchReceipt{}, false, keyErr
		}
		user, exists := s.users[userKey]
		if !exists || !identityUserMatchesDataScope(user, scope) {
			return identitymodel.IdentityEntitlementBatchReceipt{}, false, nil
		}
		assignmentKey, _ := identityWorkspaceKey(mutation.WorkspaceID, assignment.UserID, assignment.RoleID)
		next[assignmentKey] = assignment
	}
	receipt := identitymodel.IdentityEntitlementBatchReceipt{
		ID: identityID("identity_entitlement_batch", mutation.WorkspaceID, mutation.IdempotencyKey), WorkspaceID: mutation.WorkspaceID,
		ActorID: mutation.ActorID, IdempotencyKey: mutation.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint,
		Items: mutation.Items, CreatedAt: nowString(),
	}
	s.userRoles = next
	s.entitlementReceipts[receiptKey] = receipt
	return receipt, true, nil
}

func (s *MemoryIdentityStore) CreateIdentityRoleRequest(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error) {
	key, err := identityWorkspaceKey(workspaceID, request.ID)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	if request.ID == "" || request.UserID == "" || len(request.RoleIDs) == 0 {
		return identitymodel.IdentityRoleRequest{}, fmt.Errorf("role request id, user id, and roles are required")
	}
	request.RoleIDs = uniqueSortedStrings(request.RoleIDs)
	if request.Status == "" {
		request.Status = "pending"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roleRequests[key] = cloneIdentityRoleRequest(request)
	return cloneIdentityRoleRequest(request), nil
}

func (s *MemoryIdentityStore) ListIdentityRoleRequests(ctx context.Context, workspaceID, status string, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	return s.ListIdentityRoleRequestsWithinDataScope(ctx, workspaceID, status, userID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *MemoryIdentityStore) ListIdentityRoleRequestsWithinDataScope(_ context.Context, workspaceID, status string, userID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityRoleRequest, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return nil, err
	}
	status = strings.TrimSpace(status)
	userID = strings.TrimSpace(userID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []identitymodel.IdentityRoleRequest{}
	for key, request := range s.roleRequests {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if status != "" && request.Status != status {
			continue
		}
		if userID != "" && request.UserID != userID {
			continue
		}
		if !scope.Unrestricted {
			userKey, _ := identityWorkspaceKey(workspaceID, request.UserID)
			user, found := s.users[userKey]
			if !found || !identityUserMatchesDataScope(user, scope) {
				continue
			}
		}
		out = append(out, cloneIdentityRoleRequest(request))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt == out[j].CreatedAt {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out, nil
}

func (s *MemoryIdentityStore) UpdateIdentityRoleRequest(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest) error {
	key, err := identityWorkspaceKey(workspaceID, request.ID)
	if err != nil {
		return err
	}
	if request.ID == "" {
		return fmt.Errorf("role request id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roleRequests[key]; !ok {
		return fmt.Errorf("role request %q not found", request.ID)
	}
	s.roleRequests[key] = cloneIdentityRoleRequest(request)
	return nil
}
