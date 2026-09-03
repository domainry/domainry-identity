package identity

import (
	"context"
	"database/sql"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	accessreviewpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/accessreview"
	roleassignmentpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/roleassignment"
)

type identityAccessReviewQueryer = accessreviewpersistence.Queryer

func (s *SQLIdentityStore) accessReviewStore() *accessreviewpersistence.Store {
	return accessreviewpersistence.New(s, nowString, s.writeIdentityUserRoleAssignmentTx, func(ctx context.Context, tx *sql.Tx, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
		return roleassignmentpersistence.New(s, nowString).UpsertWithExecutorWithinDataScope(ctx, tx, workspaceID, assignment, scope)
	})
}

func (s *SQLIdentityStore) writeIdentityUserRoleAssignmentTx(ctx context.Context, tx *sql.Tx, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
	return s.writeIdentityUserRoleAssignment(ctx, tx, workspaceID, assignment)
}

func (s *SQLIdentityStore) CreateIdentityAccessReview(ctx context.Context, review identitymodel.IdentityAccessReview) error {
	return s.accessReviewStore().CreateIdentityAccessReview(ctx, review)
}

func (s *SQLIdentityStore) CreateIdentityAccessReviewWithinDataScope(ctx context.Context, review identitymodel.IdentityAccessReview, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	return s.accessReviewStore().CreateIdentityAccessReviewWithinDataScope(ctx, review, scope)
}

func (s *SQLIdentityStore) ListIdentityAccessReviews(ctx context.Context, workspaceID, status string) ([]identitymodel.IdentityAccessReview, error) {
	return s.accessReviewStore().ListIdentityAccessReviews(ctx, workspaceID, status)
}

func (s *SQLIdentityStore) ListIdentityAccessReviewsWithinDataScope(ctx context.Context, workspaceID, status string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityAccessReview, error) {
	return s.accessReviewStore().ListIdentityAccessReviewsWithinDataScope(ctx, workspaceID, status, scope)
}

func (s *SQLIdentityStore) GetIdentityAccessReviewItem(ctx context.Context, workspaceID, itemID string) (identitymodel.IdentityAccessReviewItem, bool, error) {
	return s.accessReviewStore().GetIdentityAccessReviewItem(ctx, workspaceID, itemID)
}

func (s *SQLIdentityStore) GetIdentityAccessReviewItemWithinDataScope(ctx context.Context, workspaceID, itemID string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewItem, bool, error) {
	return s.accessReviewStore().GetIdentityAccessReviewItemWithinDataScope(ctx, workspaceID, itemID, scope)
}

func (s *SQLIdentityStore) GetIdentityAccessReviewDecisionReceipt(ctx context.Context, workspaceID, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	return s.accessReviewStore().GetIdentityAccessReviewDecisionReceipt(ctx, workspaceID, itemID, idempotencyKey)
}

func (s *SQLIdentityStore) GetIdentityAccessReviewDecisionReceiptWithinDataScope(ctx context.Context, workspaceID, itemID, idempotencyKey string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	return s.accessReviewStore().GetIdentityAccessReviewDecisionReceiptWithinDataScope(ctx, workspaceID, itemID, idempotencyKey, scope)
}

func (s *SQLIdentityStore) ApplyIdentityAccessReviewDecision(ctx context.Context, mutation identitymodel.IdentityAccessReviewDecisionMutation) (identitymodel.IdentityAccessReviewDecisionReceipt, error) {
	return s.accessReviewStore().ApplyIdentityAccessReviewDecision(ctx, mutation)
}

func (s *SQLIdentityStore) ApplyIdentityAccessReviewDecisionWithinDataScope(ctx context.Context, mutation identitymodel.IdentityAccessReviewDecisionMutation, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	return s.accessReviewStore().ApplyIdentityAccessReviewDecisionWithinDataScope(ctx, mutation, scope)
}

func (s *SQLIdentityStore) listIdentityAccessReviewItems(ctx context.Context, workspaceID, reviewID string) ([]identitymodel.IdentityAccessReviewItem, error) {
	return s.accessReviewStore().ListItems(ctx, workspaceID, reviewID)
}

func (s *SQLIdentityStore) loadIdentityAccessReviewItem(ctx context.Context, queryer identityAccessReviewQueryer, workspaceID, itemID string) (identitymodel.IdentityAccessReviewItem, bool, error) {
	return s.accessReviewStore().LoadItem(ctx, queryer, workspaceID, itemID)
}

func (s *SQLIdentityStore) loadIdentityAccessReviewReceipt(ctx context.Context, queryer identityAccessReviewQueryer, workspaceID, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	return s.accessReviewStore().LoadReceipt(ctx, queryer, workspaceID, itemID, idempotencyKey)
}

func (s *SQLIdentityStore) loadIdentityAccessReviewAssignment(ctx context.Context, queryer identityAccessReviewQueryer, workspaceID, userID, roleID string) (identitymodel.IdentityUserRoleAssignment, bool, error) {
	return s.accessReviewStore().LoadAssignment(ctx, queryer, workspaceID, userID, roleID)
}

func (s *SQLIdentityStore) loadIdentityAccessReviewRole(ctx context.Context, queryer identityAccessReviewQueryer, workspaceID, roleID string) (identitymodel.IdentityRole, bool, error) {
	return s.accessReviewStore().LoadRole(ctx, queryer, workspaceID, roleID)
}
