package identity

import (
	"context"
	"errors"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

var errIdentitySeedTest = errors.New("identity test failure")

// identityScopedRepository is deliberately behavior-light: scoped wrapper tests
// assert context routing while the domain service's rule tests own semantics.
type identityScopedRepository struct {
	organizationUnits []identitymodel.IdentityOrganizationUnit
	users             []identitymodel.IdentityUser
	roles             []identitymodel.IdentityRole
	assignments       []identitymodel.IdentityUserRoleAssignment
	receipts          map[string]identitymodel.IdentityEntitlementBatchReceipt
	reviews           []identitymodel.IdentityAccessReview
	reviewReceipts    map[string]identitymodel.IdentityAccessReviewDecisionReceipt
	requests          []identitymodel.IdentityRoleRequest
	menus             []identitymodel.IdentityMenu
	roleMenus         []identitymodel.IdentityRoleMenuAssignment
}

func (r *identityScopedRepository) ListIdentityOrganizationUnits(context.Context, string) ([]identitymodel.IdentityOrganizationUnit, error) {
	return r.organizationUnits, nil
}
func (r *identityScopedRepository) UpsertIdentityOrganizationUnit(context.Context, string, identitymodel.IdentityOrganizationUnit) error {
	return nil
}
func (r *identityScopedRepository) UpsertIdentityOrganizationUnitsAtomically(context.Context, string, []identitymodel.IdentityOrganizationUnit) error {
	return nil
}
func (r *identityScopedRepository) ListIdentityUsers(context.Context, string) ([]identitymodel.IdentityUser, error) {
	return r.users, nil
}
func (r *identityScopedRepository) ListIdentityUsersWithinDataScope(_ context.Context, _ string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUser, error) {
	out := make([]identitymodel.IdentityUser, 0, len(r.users))
	for _, user := range r.users {
		if identityScopedTestUserMatches(user, scope) {
			out = append(out, user)
		}
	}
	return out, nil
}
func (r *identityScopedRepository) ListIdentityProfileBindingsByUser(context.Context, string, string) ([]identitymodel.IdentityProfileBinding, error) {
	return nil, nil
}
func (r *identityScopedRepository) GetIdentityUser(_ context.Context, _, id string) (identitymodel.IdentityUser, bool, error) {
	for _, user := range r.users {
		if user.ID == id {
			return user, true, nil
		}
	}
	return identitymodel.IdentityUser{}, false, nil
}
func (r *identityScopedRepository) GetIdentityUserWithinDataScope(_ context.Context, _ string, id string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityUser, bool, error) {
	for _, user := range r.users {
		if user.ID == id && identityScopedTestUserMatches(user, scope) {
			return user, true, nil
		}
	}
	return identitymodel.IdentityUser{}, false, nil
}
func (r *identityScopedRepository) UpsertIdentityUser(context.Context, string, identitymodel.IdentityUser) error {
	return nil
}
func (r *identityScopedRepository) CreateIdentityUser(_ context.Context, _ string, user identitymodel.IdentityUser) error {
	for _, existing := range r.users {
		if existing.ID == user.ID {
			return errors.New("identity user already exists")
		}
	}
	r.users = append(r.users, user)
	return nil
}
func (r *identityScopedRepository) UpsertIdentityUsersAtomically(context.Context, string, []identitymodel.IdentityUser) error {
	return nil
}
func (r *identityScopedRepository) UpdateIdentityUsersWithinDataScopeAtomically(_ context.Context, _ string, users []identitymodel.IdentityUser, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	for _, update := range users {
		matched := false
		for _, existing := range r.users {
			if existing.ID == update.ID && identityScopedTestUserMatches(existing, scope) {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	for _, update := range users {
		for index := range r.users {
			if r.users[index].ID == update.ID {
				r.users[index] = update
			}
		}
	}
	return true, nil
}
func (r *identityScopedRepository) RemoveIdentityUser(context.Context, string, string) error {
	return nil
}
func (r *identityScopedRepository) SetIdentityUserStatus(context.Context, string, string, identitymodel.IdentityStatus) error {
	return nil
}
func (r *identityScopedRepository) RemoveIdentityUserWithinDataScope(_ context.Context, _ string, userID string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	for index, user := range r.users {
		if user.ID == userID && identityScopedTestUserMatches(user, scope) {
			r.users = append(r.users[:index], r.users[index+1:]...)
			return true, nil
		}
	}
	return false, nil
}
func (r *identityScopedRepository) SetIdentityUserStatusWithinDataScope(_ context.Context, _ string, userID string, status identitymodel.IdentityStatus, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	for index, user := range r.users {
		if user.ID == userID && identityScopedTestUserMatches(user, scope) {
			r.users[index].Status = status
			return true, nil
		}
	}
	return false, nil
}

func identityScopedTestUserMatches(user identitymodel.IdentityUser, scope identitymodel.IdentityDataScopeFilter) bool {
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
func (r *identityScopedRepository) ListIdentityRoles(context.Context, string) ([]identitymodel.IdentityRole, error) {
	return r.roles, nil
}
func (r *identityScopedRepository) UpsertIdentityRole(context.Context, string, identitymodel.IdentityRole) error {
	return nil
}
func (r *identityScopedRepository) RemoveIdentityRole(context.Context, string, string) error {
	return nil
}
func (r *identityScopedRepository) SetIdentityRoleStatus(context.Context, string, string, identitymodel.IdentityStatus) error {
	return nil
}
func (r *identityScopedRepository) AssignIdentityUserRole(context.Context, string, identitymodel.IdentityUserRoleAssignment) error {
	return nil
}
func (r *identityScopedRepository) AssignIdentityUserRoleWithinDataScope(_ context.Context, _ string, assignment identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	for _, user := range r.users {
		if user.ID == assignment.UserID && identityScopedTestUserMatches(user, scope) {
			r.assignments = append(r.assignments, assignment)
			return true, nil
		}
	}
	return false, nil
}
func (r *identityScopedRepository) RemoveIdentityUserRole(context.Context, string, string, string) error {
	return nil
}
func (r *identityScopedRepository) RemoveIdentityUserRoleWithinDataScope(_ context.Context, _ string, userID, roleID string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	for _, user := range r.users {
		if user.ID != userID || !identityScopedTestUserMatches(user, scope) {
			continue
		}
		for index := range r.assignments {
			if r.assignments[index].UserID == userID && r.assignments[index].RoleID == roleID {
				r.assignments = append(r.assignments[:index], r.assignments[index+1:]...)
				break
			}
		}
		return true, nil
	}
	return false, nil
}
func (r *identityScopedRepository) ListIdentityUserRoleAssignments(context.Context, string, string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return r.assignments, nil
}
func (r *identityScopedRepository) ListIdentityUserRoleAssignmentsWithinDataScope(_ context.Context, _ string, userID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUserRoleAssignment, error) {
	allowed := map[string]bool{}
	for _, user := range r.users {
		allowed[user.ID] = identityScopedTestUserMatches(user, scope)
	}
	out := []identitymodel.IdentityUserRoleAssignment{}
	for _, assignment := range r.assignments {
		if (userID == "" || assignment.UserID == userID) && allowed[assignment.UserID] {
			out = append(out, assignment)
		}
	}
	return out, nil
}
func (r *identityScopedRepository) UpsertIdentityUserWithRoleAssignmentsWithinDataScopeAtomically(_ context.Context, _ string, user identitymodel.IdentityUser, assignments []identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	for index, existing := range r.users {
		if existing.ID == user.ID && identityScopedTestUserMatches(existing, scope) {
			r.users[index] = user
			r.assignments = append([]identitymodel.IdentityUserRoleAssignment(nil), assignments...)
			return true, nil
		}
	}
	return false, nil
}
func (r *identityScopedRepository) GetIdentityEntitlementBatchReceipt(_ context.Context, _, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	receipt, found := r.receipts[idempotencyKey]
	return receipt, found, nil
}

func (r *identityScopedRepository) GetIdentityEntitlementBatchReceiptWithinDataScope(ctx context.Context, workspaceID, idempotencyKey string, _ identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	return r.GetIdentityEntitlementBatchReceipt(ctx, workspaceID, idempotencyKey)
}
func (r *identityScopedRepository) ApplyIdentityEntitlementBatch(_ context.Context, mutation identitymodel.IdentityEntitlementBatchMutation) (identitymodel.IdentityEntitlementBatchReceipt, error) {
	if r.receipts == nil {
		r.receipts = map[string]identitymodel.IdentityEntitlementBatchReceipt{}
	}
	receipt := identitymodel.IdentityEntitlementBatchReceipt{
		ID: "receipt-" + mutation.IdempotencyKey, WorkspaceID: mutation.WorkspaceID, ActorID: mutation.ActorID,
		IdempotencyKey: mutation.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint, Items: mutation.Items, CreatedAt: "now",
	}
	r.assignments = append(r.assignments, mutation.Assignments...)
	r.receipts[mutation.IdempotencyKey] = receipt
	return receipt, nil
}

func (r *identityScopedRepository) ApplyIdentityEntitlementBatchWithinDataScope(ctx context.Context, mutation identitymodel.IdentityEntitlementBatchMutation, _ identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	receipt, err := r.ApplyIdentityEntitlementBatch(ctx, mutation)
	return receipt, err == nil, err
}

func (r *identityScopedRepository) CreateIdentityAccessReview(_ context.Context, review identitymodel.IdentityAccessReview) error {
	r.reviews = append(r.reviews, review)
	return nil
}

func (r *identityScopedRepository) CreateIdentityAccessReviewWithinDataScope(_ context.Context, review identitymodel.IdentityAccessReview, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	for _, item := range review.Items {
		allowed := false
		for _, user := range r.users {
			if user.ID == item.UserID && identityScopedTestUserMatches(user, scope) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false, nil
		}
	}
	r.reviews = append(r.reviews, review)
	return true, nil
}

func (r *identityScopedRepository) ListIdentityAccessReviews(_ context.Context, _ string, status string) ([]identitymodel.IdentityAccessReview, error) {
	out := make([]identitymodel.IdentityAccessReview, 0, len(r.reviews))
	for _, review := range r.reviews {
		if status == "" || string(review.Status) == status {
			out = append(out, review)
		}
	}
	return out, nil
}

func (r *identityScopedRepository) ListIdentityAccessReviewsWithinDataScope(_ context.Context, _ string, status string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityAccessReview, error) {
	allowed := map[string]bool{}
	for _, user := range r.users {
		allowed[user.ID] = identityScopedTestUserMatches(user, scope)
	}
	out := []identitymodel.IdentityAccessReview{}
	for _, review := range r.reviews {
		if status != "" && string(review.Status) != status {
			continue
		}
		copyReview := review
		copyReview.Items = nil
		for _, item := range review.Items {
			if allowed[item.UserID] {
				copyReview.Items = append(copyReview.Items, item)
			}
		}
		if len(copyReview.Items) > 0 {
			out = append(out, copyReview)
		}
	}
	return out, nil
}

func (r *identityScopedRepository) GetIdentityAccessReviewItem(_ context.Context, _ string, itemID string) (identitymodel.IdentityAccessReviewItem, bool, error) {
	for _, review := range r.reviews {
		for _, item := range review.Items {
			if item.ID == itemID {
				return item, true, nil
			}
		}
	}
	return identitymodel.IdentityAccessReviewItem{}, false, nil
}

func (r *identityScopedRepository) GetIdentityAccessReviewItemWithinDataScope(ctx context.Context, workspaceID, itemID string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewItem, bool, error) {
	item, found, err := r.GetIdentityAccessReviewItem(ctx, workspaceID, itemID)
	if err != nil || !found {
		return item, found, err
	}
	for _, user := range r.users {
		if user.ID == item.UserID && identityScopedTestUserMatches(user, scope) {
			return item, true, nil
		}
	}
	return identitymodel.IdentityAccessReviewItem{}, false, nil
}

func (r *identityScopedRepository) GetIdentityAccessReviewDecisionReceipt(_ context.Context, _ string, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	receipt, found := r.reviewReceipts[itemID+"\x00"+idempotencyKey]
	return receipt, found, nil
}

func (r *identityScopedRepository) GetIdentityAccessReviewDecisionReceiptWithinDataScope(ctx context.Context, workspaceID, itemID, idempotencyKey string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	if _, found, err := r.GetIdentityAccessReviewItemWithinDataScope(ctx, workspaceID, itemID, scope); err != nil || !found {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, err
	}
	return r.GetIdentityAccessReviewDecisionReceipt(ctx, workspaceID, itemID, idempotencyKey)
}

func (r *identityScopedRepository) ApplyIdentityAccessReviewDecision(_ context.Context, mutation identitymodel.IdentityAccessReviewDecisionMutation) (identitymodel.IdentityAccessReviewDecisionReceipt, error) {
	if r.reviewReceipts == nil {
		r.reviewReceipts = map[string]identitymodel.IdentityAccessReviewDecisionReceipt{}
	}
	key := mutation.ItemID + "\x00" + mutation.Request.IdempotencyKey
	if receipt, found := r.reviewReceipts[key]; found {
		receipt.Replayed = true
		return receipt, nil
	}
	item, _, _ := r.GetIdentityAccessReviewItem(context.Background(), mutation.WorkspaceID, mutation.ItemID)
	item.Status, item.Decision, item.ReviewerID, item.Reason, item.Version = "decided", mutation.Request.Decision, mutation.ReviewerID, mutation.Request.Reason, item.Version+1
	receipt := identitymodel.IdentityAccessReviewDecisionReceipt{
		ID: "receipt-" + mutation.Request.IdempotencyKey, WorkspaceID: mutation.WorkspaceID, ItemID: mutation.ItemID,
		IdempotencyKey: mutation.Request.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint, Item: item, CreatedAt: "now",
	}
	r.reviewReceipts[key] = receipt
	return receipt, nil
}
func (r *identityScopedRepository) ApplyIdentityAccessReviewDecisionWithinDataScope(ctx context.Context, mutation identitymodel.IdentityAccessReviewDecisionMutation, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	if _, found, err := r.GetIdentityAccessReviewItemWithinDataScope(ctx, mutation.WorkspaceID, mutation.ItemID, scope); err != nil || !found {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, err
	}
	receipt, err := r.ApplyIdentityAccessReviewDecision(ctx, mutation)
	return receipt, true, err
}
func (r *identityScopedRepository) CreateIdentityRoleRequest(_ context.Context, _ string, request identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error) {
	return request, nil
}
func (r *identityScopedRepository) ListIdentityRoleRequests(context.Context, string, string, string) ([]identitymodel.IdentityRoleRequest, error) {
	return r.requests, nil
}
func (r *identityScopedRepository) ListIdentityRoleRequestsWithinDataScope(_ context.Context, _ string, status, userID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityRoleRequest, error) {
	allowed := map[string]bool{}
	for _, user := range r.users {
		allowed[user.ID] = identityScopedTestUserMatches(user, scope)
	}
	out := []identitymodel.IdentityRoleRequest{}
	for _, request := range r.requests {
		if (status == "" || request.Status == status) && (userID == "" || request.UserID == userID) && allowed[request.UserID] {
			out = append(out, request)
		}
	}
	return out, nil
}
func (r *identityScopedRepository) ApplyIdentityRoleRequestDecisionWithinDataScope(_ context.Context, _ string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, expectedStatus string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	for _, user := range r.users {
		if user.ID != request.UserID || !identityScopedTestUserMatches(user, scope) {
			continue
		}
		for index := range r.requests {
			if r.requests[index].ID == request.ID && r.requests[index].Status == expectedStatus {
				r.requests[index] = request
				r.assignments = append(r.assignments, assignments...)
				return true, nil
			}
		}
	}
	return false, nil
}
func (r *identityScopedRepository) UpdateIdentityRoleRequest(context.Context, string, identitymodel.IdentityRoleRequest) error {
	return nil
}
func (r *identityScopedRepository) SetIdentityRolePermissions(context.Context, string, string, []string) error {
	return nil
}
func (r *identityScopedRepository) ListIdentityRolePermissionAssignments(context.Context, string, string) ([]identitymodel.IdentityRolePermissionAssignment, error) {
	return nil, nil
}
func (r *identityScopedRepository) SetIdentityRoleFieldPermissions(context.Context, string, string, []identitymodel.IdentityFieldPermission) error {
	return nil
}
func (r *identityScopedRepository) ListIdentityRoleFieldPermissions(context.Context, string, string) ([]identitymodel.IdentityFieldPermission, error) {
	return nil, nil
}
func (r *identityScopedRepository) ListIdentityMenus(context.Context, string) ([]identitymodel.IdentityMenu, error) {
	return r.menus, nil
}
func (r *identityScopedRepository) UpsertIdentityMenu(context.Context, string, identitymodel.IdentityMenu) error {
	return nil
}
func (r *identityScopedRepository) RemoveIdentityMenu(context.Context, string, string) error {
	return nil
}
func (r *identityScopedRepository) SetIdentityRoleMenus(context.Context, string, string, []string) error {
	return nil
}
func (r *identityScopedRepository) ListIdentityRoleMenuAssignments(context.Context, string, string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	return r.roleMenus, nil
}
