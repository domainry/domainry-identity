package identity_test

import (
	"path/filepath"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestAccessReviewDecisionIsAtomicAuditableAndIdempotent(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "access-review.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityUser(t.Context(), "workspace-primary", identitymodel.IdentityUser{ID: "user-1", Name: "User", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityRole(t.Context(), "workspace-primary", identitymodel.IdentityRole{ID: "role-1", Key: "privileged", Label: "Privileged", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignIdentityUserRole(t.Context(), "workspace-primary", identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "role-1", Source: "manual", Status: "active", GrantedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	review := identitymodel.IdentityAccessReview{
		ID: "review-1", WorkspaceID: "workspace-primary", PeriodStart: "2026-01-01T00:00:00Z", PeriodEnd: "2026-03-31T00:00:00Z",
		DueAt: "2026-04-15T00:00:00Z", Status: identitymodel.IdentityAccessReviewOpen, CreatedBy: "admin",
		CreatedAt: "2026-04-01T00:00:00Z", UpdatedAt: "2026-04-01T00:00:00Z",
		Items: []identitymodel.IdentityAccessReviewItem{{
			ID: "item-1", ReviewID: "review-1", UserID: "user-1", RoleID: "role-1", RoleKey: "privileged",
			RiskLevel: identitymodel.IdentityRoleRiskPrivileged, Priority: "critical", Status: "pending", Version: 1,
			CreatedAt: "2026-04-01T00:00:00Z", UpdatedAt: "2026-04-01T00:00:00Z",
		}},
	}
	if err := store.CreateIdentityAccessReview(t.Context(), review); err != nil {
		t.Fatal(err)
	}
	mutation := identitymodel.IdentityAccessReviewDecisionMutation{
		WorkspaceID: "workspace-primary", ItemID: "item-1", ReviewerID: "reviewer",
		RequestFingerprint: "fingerprint-1",
		Request: identitymodel.IdentityAccessReviewDecisionRequest{
			Decision: identitymodel.IdentityAccessReviewRevoke, Reason: "no longer required",
			ExpectedVersion: 1, IdempotencyKey: "decision-1",
		},
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `CREATE TRIGGER fail_access_review_receipt BEFORE INSERT ON _identity_access_review_receipts
		BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), mutation); err == nil {
		t.Fatal("injected receipt failure was ignored")
	}
	assignments, err := store.ListIdentityUserRoleAssignments(t.Context(), "workspace-primary", "user-1")
	if err != nil || len(assignments) != 1 {
		t.Fatalf("assignment mutation was not rolled back: %#v err=%v", assignments, err)
	}
	item, found, err := store.GetIdentityAccessReviewItem(t.Context(), "workspace-primary", "item-1")
	if err != nil || !found || item.Status != "pending" || item.Version != 1 {
		t.Fatalf("item mutation was not rolled back: %#v found=%v err=%v", item, found, err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `DROP TRIGGER fail_access_review_receipt`); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.ApplyIdentityAccessReviewDecision(t.Context(), mutation)
	if err != nil || receipt.Replayed || receipt.Item.Status != "decided" || receipt.Item.Version != 2 {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	replay, err := store.ApplyIdentityAccessReviewDecision(t.Context(), mutation)
	if err != nil || !replay.Replayed || replay.ID != receipt.ID {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	reused := mutation
	reused.RequestFingerprint = "fingerprint-2"
	if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), reused); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("reused idempotency key error=%v", err)
	}
	assignments, err = store.ListIdentityUserRoleAssignments(t.Context(), "workspace-primary", "user-1")
	if err != nil || len(assignments) != 0 {
		t.Fatalf("revoke was not applied exactly once: %#v err=%v", assignments, err)
	}
	reviews, err := store.ListIdentityAccessReviews(t.Context(), "workspace-primary", string(identitymodel.IdentityAccessReviewCompleted))
	if err != nil || len(reviews) != 1 || len(reviews[0].Items) != 1 || reviews[0].Items[0].Decision != identitymodel.IdentityAccessReviewRevoke {
		t.Fatalf("completed review=%#v err=%v", reviews, err)
	}
}

func TestAccessReviewStoreValidatesInputsAndSupportsEveryDecisionShape(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "access-review-shapes.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}

	for _, invalid := range []identitymodel.IdentityAccessReview{
		{WorkspaceID: ""},
		{WorkspaceID: "workspace-primary", CreatedBy: "admin", Items: []identitymodel.IdentityAccessReviewItem{{ID: "item"}}},
		{WorkspaceID: "workspace-primary", ID: "review", Items: []identitymodel.IdentityAccessReviewItem{{ID: "item"}}},
		{WorkspaceID: "workspace-primary", ID: "review", CreatedBy: "admin"},
	} {
		if err := store.CreateIdentityAccessReview(t.Context(), invalid); err == nil {
			t.Fatalf("invalid review was accepted: %#v", invalid)
		}
	}
	if _, err := store.ListIdentityAccessReviews(t.Context(), "", ""); err == nil {
		t.Fatal("invalid list workspace was accepted")
	}
	if _, found, err := store.GetIdentityAccessReviewItem(t.Context(), "", "item"); err == nil || found {
		t.Fatalf("invalid item workspace found=%v err=%v", found, err)
	}
	if _, found, err := store.GetIdentityAccessReviewDecisionReceipt(t.Context(), "", "item", "key"); err == nil || found {
		t.Fatalf("invalid receipt workspace found=%v err=%v", found, err)
	}
	if _, found, err := store.GetIdentityAccessReviewItem(t.Context(), "workspace-primary", "missing"); err != nil || found {
		t.Fatalf("missing item found=%v err=%v", found, err)
	}
	if _, found, err := store.GetIdentityAccessReviewDecisionReceipt(t.Context(), "workspace-primary", "missing", "key"); err != nil || found {
		t.Fatalf("missing receipt found=%v err=%v", found, err)
	}

	for _, role := range []identitymodel.IdentityRole{
		{ID: "role-current", Key: "current", Label: "Current", Status: identitymodel.IdentityStatusActive},
		{ID: "role-reduced", Key: "reduced", Label: "Reduced", Status: identitymodel.IdentityStatusActive},
	} {
		if err := store.UpsertIdentityRole(t.Context(), "workspace-primary", role); err != nil {
			t.Fatal(err)
		}
	}
	userIDs := []string{"keep", "expiry", "reduce", "missing-revoke", "missing-expiry", "missing-reduce", "bad-replacement", "same-replacement", "unknown", "version"}
	for _, userID := range userIDs {
		if err := store.UpsertIdentityUser(t.Context(), "workspace-primary", identitymodel.IdentityUser{ID: userID, Name: userID, Status: identitymodel.IdentityStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	for _, userID := range []string{"keep", "expiry", "reduce", "bad-replacement", "same-replacement", "unknown", "version"} {
		if err := store.AssignIdentityUserRole(t.Context(), "workspace-primary", identitymodel.IdentityUserRoleAssignment{
			UserID: userID, RoleID: "role-current", Source: "manual", Status: "active", GrantedBy: "admin",
		}); err != nil {
			t.Fatal(err)
		}
	}
	items := make([]identitymodel.IdentityAccessReviewItem, 0, len(userIDs))
	for _, userID := range userIDs {
		items = append(items, identitymodel.IdentityAccessReviewItem{
			ID: "item-" + userID, ReviewID: "review-shapes", UserID: userID, RoleID: "role-current", RoleKey: "current",
			RiskLevel: identitymodel.IdentityRoleRiskNormal, Priority: "normal", PriorityReasons: []string{},
			Status: "pending", Version: 1, CreatedAt: "2026-04-01T00:00:00Z", UpdatedAt: "2026-04-01T00:00:00Z",
		})
	}
	review := identitymodel.IdentityAccessReview{
		ID: "review-shapes", WorkspaceID: "workspace-primary", PeriodStart: "2026-01-01T00:00:00Z", PeriodEnd: "2026-03-31T00:00:00Z",
		DueAt: "2026-04-15T00:00:00Z", Status: identitymodel.IdentityAccessReviewOpen, CreatedBy: "admin",
		CreatedAt: "2026-04-01T00:00:00Z", UpdatedAt: "2026-04-01T00:00:00Z", Items: items,
	}
	if err := store.CreateIdentityAccessReview(t.Context(), review); err != nil {
		t.Fatal(err)
	}
	if reviews, err := store.ListIdentityAccessReviews(t.Context(), "workspace-primary", ""); err != nil || len(reviews) != 1 || len(reviews[0].Items) != len(items) {
		t.Fatalf("unfiltered reviews=%#v err=%v", reviews, err)
	}

	mutation := func(userID string, decision identitymodel.IdentityAccessReviewDecision) identitymodel.IdentityAccessReviewDecisionMutation {
		return identitymodel.IdentityAccessReviewDecisionMutation{
			WorkspaceID: "workspace-primary", ItemID: "item-" + userID, ReviewerID: "reviewer", RequestFingerprint: "fingerprint-" + userID,
			Request: identitymodel.IdentityAccessReviewDecisionRequest{
				Decision: decision, Reason: "reviewed", ExpectedVersion: 1, IdempotencyKey: "decision-" + userID,
			},
		}
	}
	invalidMutations := []identitymodel.IdentityAccessReviewDecisionMutation{
		{},
		{WorkspaceID: "workspace-primary", ReviewerID: "reviewer", RequestFingerprint: "fingerprint", Request: identitymodel.IdentityAccessReviewDecisionRequest{IdempotencyKey: "key"}},
		{WorkspaceID: "workspace-primary", ItemID: "item", RequestFingerprint: "fingerprint", Request: identitymodel.IdentityAccessReviewDecisionRequest{IdempotencyKey: "key"}},
		{WorkspaceID: "workspace-primary", ItemID: "item", ReviewerID: "reviewer", RequestFingerprint: "fingerprint"},
		{WorkspaceID: "workspace-primary", ItemID: "item", ReviewerID: "reviewer", Request: identitymodel.IdentityAccessReviewDecisionRequest{IdempotencyKey: "key"}},
	}
	for _, invalid := range invalidMutations {
		if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), invalid); err == nil {
			t.Fatalf("invalid mutation was accepted: %#v", invalid)
		}
	}
	missingItem := mutation("does-not-exist", identitymodel.IdentityAccessReviewKeep)
	if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), missingItem); apperror.CodeOf(err) != "backend.identity.access_review_item_not_found" {
		t.Fatalf("missing item error=%v", err)
	}
	versionConflict := mutation("version", identitymodel.IdentityAccessReviewKeep)
	versionConflict.Request.ExpectedVersion = 2
	if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), versionConflict); apperror.CodeOf(err) != "backend.identity.access_review_concurrent_decision" {
		t.Fatalf("version conflict=%v", err)
	}

	for _, userID := range []string{"keep", "missing-revoke"} {
		request := mutation(userID, identitymodel.IdentityAccessReviewKeep)
		if userID == "missing-revoke" {
			request.Request.Decision = identitymodel.IdentityAccessReviewRevoke
		}
		if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), request); err != nil {
			t.Fatalf("%s decision: %v", userID, err)
		}
	}
	expiry := mutation("expiry", identitymodel.IdentityAccessReviewSetExpiry)
	expiry.Request.ExpiresAt = "2026-12-31T00:00:00Z"
	if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), expiry); err != nil {
		t.Fatalf("expiry decision: %v", err)
	}
	reduce := mutation("reduce", identitymodel.IdentityAccessReviewReduceScope)
	reduce.Request.ReplacementRoleID = "role-reduced"
	if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), reduce); err != nil {
		t.Fatalf("reduce decision: %v", err)
	}

	errorCases := []struct {
		name string
		in   identitymodel.IdentityAccessReviewDecisionMutation
		code string
	}{
		{name: "missing expiry assignment", in: mutation("missing-expiry", identitymodel.IdentityAccessReviewSetExpiry), code: "backend.identity.access_review_assignment_missing"},
		{name: "missing reduction assignment", in: mutation("missing-reduce", identitymodel.IdentityAccessReviewReduceScope), code: "backend.identity.access_review_assignment_missing"},
		{name: "blank replacement", in: mutation("same-replacement", identitymodel.IdentityAccessReviewReduceScope), code: "backend.identity.access_review_replacement_role_required"},
		{name: "unknown decision", in: mutation("unknown", "unknown"), code: "backend.identity.access_review_decision_invalid"},
	}
	same := mutation("same-replacement", identitymodel.IdentityAccessReviewReduceScope)
	same.Request.ReplacementRoleID = "role-current"
	errorCases = append(errorCases, struct {
		name string
		in   identitymodel.IdentityAccessReviewDecisionMutation
		code string
	}{name: "same replacement", in: same, code: "backend.identity.access_review_replacement_role_required"})
	unknownRole := mutation("bad-replacement", identitymodel.IdentityAccessReviewReduceScope)
	unknownRole.Request.ReplacementRoleID = "role-missing"
	errorCases = append(errorCases, struct {
		name string
		in   identitymodel.IdentityAccessReviewDecisionMutation
		code string
	}{name: "unknown replacement", in: unknownRole, code: "backend.identity.role_not_found"})
	for _, test := range errorCases {
		if test.in.Request.Decision == identitymodel.IdentityAccessReviewSetExpiry {
			test.in.Request.ExpiresAt = "2026-12-31T00:00:00Z"
		}
		if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), test.in); apperror.CodeOf(err) != test.code {
			t.Fatalf("%s code=%q err=%v", test.name, apperror.CodeOf(err), err)
		}
	}
}
