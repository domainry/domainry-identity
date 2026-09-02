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
func (r *identityScopedRepository) UpsertIdentityUser(context.Context, string, identitymodel.IdentityUser) error {
	return nil
}
func (r *identityScopedRepository) UpsertIdentityUsersAtomically(context.Context, string, []identitymodel.IdentityUser) error {
	return nil
}
func (r *identityScopedRepository) RemoveIdentityUser(context.Context, string, string) error {
	return nil
}
func (r *identityScopedRepository) SetIdentityUserStatus(context.Context, string, string, identitymodel.IdentityStatus) error {
	return nil
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
func (r *identityScopedRepository) RemoveIdentityUserRole(context.Context, string, string, string) error {
	return nil
}
func (r *identityScopedRepository) ListIdentityUserRoleAssignments(context.Context, string, string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	return r.assignments, nil
}
func (r *identityScopedRepository) GetIdentityEntitlementBatchReceipt(_ context.Context, _, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	receipt, found := r.receipts[idempotencyKey]
	return receipt, found, nil
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

func (r *identityScopedRepository) CreateIdentityAccessReview(_ context.Context, review identitymodel.IdentityAccessReview) error {
	r.reviews = append(r.reviews, review)
	return nil
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

func (r *identityScopedRepository) GetIdentityAccessReviewDecisionReceipt(_ context.Context, _ string, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	receipt, found := r.reviewReceipts[itemID+"\x00"+idempotencyKey]
	return receipt, found, nil
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
func (r *identityScopedRepository) CreateIdentityRoleRequest(_ context.Context, _ string, request identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error) {
	return request, nil
}
func (r *identityScopedRepository) ListIdentityRoleRequests(context.Context, string, string, string) ([]identitymodel.IdentityRoleRequest, error) {
	return r.requests, nil
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
func (r *identityScopedRepository) SetIdentityRoleDataScopes(context.Context, string, string, []identitymodel.IdentityDataScopePolicy) error {
	return nil
}
func (r *identityScopedRepository) ListIdentityRoleDataScopes(context.Context, string, string) ([]identitymodel.IdentityDataScopePolicy, error) {
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
