package identity_test

import (
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestCreatedReviewAndRoleRequestReturnAssignedRowIDs(t *testing.T) {
	database, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "created-identities.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), database.DB(), database.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	for _, userID := range []string{"user-one", "user-two"} {
		if err := store.UpsertIdentityUser(t.Context(), "workspace", identitymodel.IdentityUser{UserID: userID, Name: userID, Email: userID + "@example.test", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	input := identitymodel.IdentityAccessReview{
		ID: 9999, ReviewID: "review-business", WorkspaceID: "workspace", CreatedBy: "reviewer", Status: identitymodel.IdentityAccessReviewOpen,
		PeriodStart: "2026-10-01T00:00:00Z", PeriodEnd: "2026-10-20T00:00:00Z", DueAt: "2026-11-01T00:00:00Z", CreatedAt: "2026-10-22T00:00:00Z", UpdatedAt: "2026-10-22T00:00:00Z",
		Items: []identitymodel.IdentityAccessReviewItem{
			{ID: 8888, ReviewItemID: "item-business-one", UserID: "user-one", RoleID: "role", RoleKey: "role", RiskLevel: identitymodel.IdentityRoleRiskNormal, Priority: "normal", Status: "pending", Version: 1},
			{ID: 7777, ReviewItemID: "item-business-two", UserID: "user-two", RoleID: "role", RoleKey: "role", RiskLevel: identitymodel.IdentityRoleRiskNormal, Priority: "normal", Status: "pending", Version: 1},
		},
	}
	created, allowed, err := store.CreateIdentityAccessReviewWithinDataScope(t.Context(), input, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
	if err != nil || !allowed || created.ID <= 0 || created.ID == input.ID || created.ReviewID != input.ReviewID {
		t.Fatalf("review=%+v allowed=%v err=%v", created, allowed, err)
	}
	for index, item := range created.Items {
		var storedID int64
		if err := database.DB().QueryRowContext(t.Context(), `SELECT id FROM _identity_access_review_items WHERE review_item_id=?`, item.ReviewItemID).Scan(&storedID); err != nil {
			t.Fatal(err)
		}
		if item.ID <= 0 || item.ID == input.Items[index].ID || item.ID != storedID || item.ReviewItemID != input.Items[index].ReviewItemID {
			t.Fatalf("item=%+v storedID=%d input=%+v", item, storedID, input.Items[index])
		}
	}
	if input.Items[0].ID != 8888 || input.Items[1].ID != 7777 {
		t.Fatal("create mutated the caller's input")
	}
	request, err := store.CreateIdentityRoleRequest(t.Context(), "workspace", identitymodel.IdentityRoleRequest{ID: 6666, RoleRequestID: "request-business", UserID: "user-one", RoleIDs: []string{"role"}})
	if err != nil || request.ID <= 0 || request.ID == 6666 || request.RoleRequestID != "request-business" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
	var storedRequestID int64
	if err := database.DB().QueryRowContext(t.Context(), `SELECT id FROM _identity_role_requests WHERE role_request_id=?`, request.RoleRequestID).Scan(&storedRequestID); err != nil || storedRequestID != request.ID {
		t.Fatalf("stored request ID=%d returned=%d err=%v", storedRequestID, request.ID, err)
	}

	// A candidate outside the workspace must roll back both the review header
	// and any earlier allowed item; no partially assigned identities escape.
	input.ReviewID = "review-denied"
	input.Items[0].ReviewItemID = "denied-item-one"
	input.Items[1].ReviewItemID, input.Items[1].UserID = "denied-item-two", "foreign-user"
	refused, allowed, err := store.CreateIdentityAccessReviewWithinDataScope(t.Context(), input, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
	if err != nil || allowed || refused.ID != 0 {
		t.Fatalf("refused=%+v allowed=%v err=%v", refused, allowed, err)
	}
	for _, table := range []string{"_identity_access_reviews", "_identity_access_review_items"} {
		var count int
		if err := database.DB().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table+" WHERE review_id=?", input.ReviewID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("partial %s rows=%d err=%v", table, count, err)
		}
	}
}
