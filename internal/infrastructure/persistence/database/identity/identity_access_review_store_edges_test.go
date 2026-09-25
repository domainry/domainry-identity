package identity

import (
	"database/sql/driver"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

var accessReviewOperationColumns = []string{"id", "resource_id", "request_fingerprint", "requested_by", "result_json", "created_at", "status"}

const accessReviewReceiptJSON = `{"id":"receipt","workspace_id":"workspace","item_id":"item","idempotency_key":"key","request_fingerprint":"fingerprint","item":{"id":"item","created_at":1700000000000,"updated_at":1700000000000},"created_at":1700000000000}`

func accessReviewOperationRow(fingerprint, resultJSON string) []driver.Value {
	return []driver.Value{"receipt", "item", fingerprint, "reviewer", resultJSON, int64(1_700_000_000_000), "succeeded"}
}

func scriptedAccessReviewOperations(state *identitySQLState) (*SQLIdentityStore, func()) {
	store, closeDB := scriptedSQLIdentity(state)
	store.BindOperationsPersistence()
	return store, closeDB
}

func accessReviewItemColumns() []string {
	return []string{
		"id", "review_id", "user_id", "role_id", "role_key", "binding_key", "profile_id",
		"risk_level", "priority", "priority_reasons_json", "last_used_at", "status", "decision", "replacement_role_id",
		"expires_at", "reviewer_id", "reason", "decided_at", "version", "created_at", "updated_at",
	}
}

func accessReviewItemRow(status string, version int64) []driver.Value {
	return []driver.Value{
		"item", "review", "user", "role", "role-key", nil, nil,
		"normal", int64(1), `["reason"]`, nil, status, nil, nil,
		nil, nil, nil, nil, version, int64(1_700_000_000_000), int64(1_700_000_000_000),
	}
}

func accessReviewAssignmentColumns() []string {
	return []string{
		"binding_key", "profile_id", "source", "status", "valid_from", "valid_until",
		"granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at",
	}
}

func accessReviewAssignmentRow() []driver.Value {
	return []driver.Value{nil, nil, "manual", "active", nil, nil, nil, nil, nil, nil, nil, nil, int64(1_700_000_000_000), int64(1_700_000_000_000)}
}

func validAccessReviewMutation(decision identitymodel.IdentityAccessReviewDecision) identitymodel.IdentityAccessReviewDecisionMutation {
	return identitymodel.IdentityAccessReviewDecisionMutation{
		WorkspaceID: "workspace", ItemID: "item", ReviewerID: "reviewer", RequestFingerprint: "fingerprint",
		Request: identitymodel.IdentityAccessReviewDecisionRequest{
			Decision: decision, ExpectedVersion: 1, IdempotencyKey: "key", Reason: "reason",
		},
	}
}

func TestCreateIdentityAccessReviewFailureStages(t *testing.T) {
	review := identitymodel.IdentityAccessReview{
		ID: "review", WorkspaceID: "workspace", CreatedBy: "creator",
		Items: []identitymodel.IdentityAccessReviewItem{{ID: "item", PriorityReasons: []string{"reason"}}},
	}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if err := store.CreateIdentityAccessReview(t.Context(), identitymodel.IdentityAccessReview{}); err == nil {
		t.Fatal("invalid review accepted")
	}
	closeDB()
	for _, state := range []*identitySQLState{
		{beginErr: errProfileBindingSQL},
		{execFailAt: 1, failure: errProfileBindingSQL},
		{execFailAt: 2, failure: errProfileBindingSQL},
		{commitErr: errProfileBindingSQL},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if err := store.CreateIdentityAccessReview(t.Context(), review); err == nil {
			t.Fatal("review write failure ignored")
		}
		closeDB()
	}
}

func TestListIdentityAccessReviewsFailureStages(t *testing.T) {
	reviewColumns := []string{"id", "period_start", "period_end", "due_at", "status", "created_by", "created_at", "updated_at"}
	reviewRow := []driver.Value{"review", "start", "end", "due", "open", "creator", "created", "updated"}
	for _, state := range []*identitySQLState{
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{querySteps: []identitySQLQueryStep{{columns: []string{"only"}, rows: [][]driver.Value{{"value"}}}}},
		{querySteps: []identitySQLQueryStep{{columns: reviewColumns, nextErr: errProfileBindingSQL}}},
		{
			queryFailAt: 2, failure: errProfileBindingSQL,
			querySteps: []identitySQLQueryStep{{columns: reviewColumns, rows: [][]driver.Value{reviewRow}}},
		},
	} {
		store, closeDB := scriptedSQLIdentity(state)
		if _, err := store.ListIdentityAccessReviews(t.Context(), "workspace", " open "); err == nil {
			t.Fatal("review list failure ignored")
		}
		closeDB()
	}
}

func TestIdentityAccessReviewLoaderEdges(t *testing.T) {
	itemColumns, itemRow := accessReviewItemColumns(), accessReviewItemRow("pending", 1)
	badItemRow := append([]driver.Value(nil), itemRow...)
	badItemRow[10] = "{"
	for _, state := range []*identitySQLState{
		{},
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{querySteps: []identitySQLQueryStep{{columns: itemColumns, rows: [][]driver.Value{badItemRow}}}},
		{querySteps: []identitySQLQueryStep{{columns: itemColumns, rows: [][]driver.Value{itemRow}}}},
	} {
		store, closeDB := scriptedSQLIdentity(state)
		item, found, err := store.GetIdentityAccessReviewItem(t.Context(), "workspace", "item")
		closeDB()
		if err == nil && found && item.ID != "item" {
			t.Fatalf("item=%#v found=%v err=%v", item, found, err)
		}
	}

	for _, resultJSON := range []string{"{", accessReviewReceiptJSON} {
		store, closeDB := scriptedAccessReviewOperations(&identitySQLState{querySteps: []identitySQLQueryStep{{
			columns: accessReviewOperationColumns, rows: [][]driver.Value{accessReviewOperationRow("fingerprint", resultJSON)},
		}}})
		receipt, found, err := store.GetIdentityAccessReviewDecisionReceipt(t.Context(), "workspace", "item", "key")
		if resultJSON == "{" && err == nil {
			t.Fatal("invalid receipt JSON accepted")
		}
		if resultJSON != "{" && (err != nil || !found || receipt.RequestFingerprint != "fingerprint") {
			t.Fatalf("receipt=%#v found=%v err=%v", receipt, found, err)
		}
		closeDB()
	}
	store, closeDB := scriptedAccessReviewOperations(&identitySQLState{})
	if _, found, err := store.GetIdentityAccessReviewDecisionReceipt(t.Context(), "workspace", "item", "key"); err != nil || found {
		t.Fatalf("missing receipt found=%v err=%v", found, err)
	}
	closeDB()
}

func TestIdentityAccessReviewAssignmentAndRoleLoaderEdges(t *testing.T) {
	for _, state := range []*identitySQLState{
		{},
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{querySteps: []identitySQLQueryStep{{columns: accessReviewAssignmentColumns(), rows: [][]driver.Value{accessReviewAssignmentRow()}}}},
	} {
		store, closeDB := scriptedSQLIdentity(state)
		assignment, found, err := store.loadIdentityAccessReviewAssignment(t.Context(), store.db, "workspace", "user", "role")
		closeDB()
		if err == nil && found && assignment.UserID != "user" {
			t.Fatalf("assignment=%#v", assignment)
		}
	}
	roleColumns := []string{"id", "role_key", "label", "description", "status"}
	for _, state := range []*identitySQLState{
		{},
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{querySteps: []identitySQLQueryStep{{columns: roleColumns, rows: [][]driver.Value{{"role", "key", "Role", "", "active"}}}}},
	} {
		store, closeDB := scriptedSQLIdentity(state)
		role, found, err := store.loadIdentityAccessReviewRole(t.Context(), store.db, "workspace", "role")
		closeDB()
		if err == nil && found && role.ID != "role" {
			t.Fatalf("role=%#v", role)
		}
	}
}

func accessReviewKeepQueries() []identitySQLQueryStep {
	return []identitySQLQueryStep{
		{},
		{columns: accessReviewItemColumns(), rows: [][]driver.Value{accessReviewItemRow("pending", 1)}},
		{},
		{columns: []string{"count"}, rows: [][]driver.Value{{int64(0)}}},
	}
}

func TestApplyIdentityAccessReviewDecisionPipelineFailures(t *testing.T) {
	mutation := validAccessReviewMutation(identitymodel.IdentityAccessReviewKeep)
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), identitymodel.IdentityAccessReviewDecisionMutation{}); err == nil {
		t.Fatal("invalid decision accepted")
	}
	closeDB()
	for _, state := range []*identitySQLState{
		{beginErr: errProfileBindingSQL},
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{queryFailAt: 2, failure: errProfileBindingSQL, querySteps: []identitySQLQueryStep{{}}},
		{querySteps: []identitySQLQueryStep{{}, {}}},
		{querySteps: []identitySQLQueryStep{{}, {columns: accessReviewItemColumns(), rows: [][]driver.Value{accessReviewItemRow("decided", 1)}}}},
		{queryFailAt: 3, failure: errProfileBindingSQL, querySteps: []identitySQLQueryStep{{}, {columns: accessReviewItemColumns(), rows: [][]driver.Value{accessReviewItemRow("pending", 1)}}}},
		{execFailAt: 1, failure: errProfileBindingSQL, querySteps: accessReviewKeepQueries()[:3]},
		{rowsFailAt: 1, failure: errProfileBindingSQL, querySteps: accessReviewKeepQueries()[:3]},
		{rowsZeroAt: 1, querySteps: accessReviewKeepQueries()[:3]},
		{queryFailAt: 4, failure: errProfileBindingSQL, querySteps: accessReviewKeepQueries()[:3]},
		{execFailAt: 2, failure: errProfileBindingSQL, querySteps: accessReviewKeepQueries()},
		{execFailAt: 3, failure: errProfileBindingSQL, querySteps: accessReviewKeepQueries()},
		{commitErr: errProfileBindingSQL, querySteps: accessReviewKeepQueries()},
	} {
		store, closeDB = scriptedAccessReviewOperations(state)
		if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), mutation); err == nil {
			t.Fatal("decision pipeline failure ignored")
		}
		closeDB()
	}
}

func TestApplyIdentityAccessReviewDecisionReplayEdges(t *testing.T) {
	mutation := validAccessReviewMutation(identitymodel.IdentityAccessReviewKeep)
	for _, fingerprint := range []string{"other", "fingerprint"} {
		store, closeDB := scriptedAccessReviewOperations(&identitySQLState{querySteps: []identitySQLQueryStep{{
			columns: accessReviewOperationColumns, rows: [][]driver.Value{accessReviewOperationRow(fingerprint, accessReviewReceiptJSON)},
		}}})
		receipt, err := store.ApplyIdentityAccessReviewDecision(t.Context(), mutation)
		if fingerprint == "other" && apperror.CodeOf(err) != "backend.idempotency_key_reused" {
			t.Fatalf("reused key error=%v", err)
		}
		if fingerprint == "fingerprint" && (err != nil || !receipt.Replayed) {
			t.Fatalf("replay=%#v err=%v", receipt, err)
		}
		closeDB()
	}
}

func TestApplyIdentityAccessReviewDecisionMutationSpecificFailures(t *testing.T) {
	itemStep := identitySQLQueryStep{columns: accessReviewItemColumns(), rows: [][]driver.Value{accessReviewItemRow("pending", 1)}}
	assignmentStep := identitySQLQueryStep{columns: accessReviewAssignmentColumns(), rows: [][]driver.Value{accessReviewAssignmentRow()}}
	roleStep := identitySQLQueryStep{columns: []string{"id", "role_key", "label", "description", "status"}, rows: [][]driver.Value{{"replacement", "replacement", "Replacement", "", "active"}}}

	revoke := validAccessReviewMutation(identitymodel.IdentityAccessReviewRevoke)
	store, closeDB := scriptedAccessReviewOperations(&identitySQLState{
		querySteps: []identitySQLQueryStep{{}, itemStep, assignmentStep}, execFailAt: 1, failure: errProfileBindingSQL,
	})
	if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), revoke); err == nil {
		t.Fatal("revoke delete failure ignored")
	}
	closeDB()

	reduce := validAccessReviewMutation(identitymodel.IdentityAccessReviewReduceScope)
	reduce.Request.ReplacementRoleID = "replacement"
	for _, state := range []*identitySQLState{
		{querySteps: []identitySQLQueryStep{{}, itemStep, {}}},
		{queryFailAt: 4, failure: errProfileBindingSQL, querySteps: []identitySQLQueryStep{{}, itemStep, assignmentStep}},
		{querySteps: []identitySQLQueryStep{{}, itemStep, assignmentStep, {}}},
		{querySteps: []identitySQLQueryStep{{}, itemStep, assignmentStep, roleStep}, execFailAt: 1, failure: errProfileBindingSQL},
		{querySteps: []identitySQLQueryStep{{}, itemStep, assignmentStep, roleStep}, execFailAt: 2, failure: errProfileBindingSQL},
	} {
		store, closeDB = scriptedAccessReviewOperations(state)
		if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), reduce); err == nil {
			t.Fatal("reduce-scope failure ignored")
		}
		closeDB()
	}

	expiry := validAccessReviewMutation(identitymodel.IdentityAccessReviewSetExpiry)
	expiry.Request.ExpiresAt = "2030-01-01T00:00:00Z"
	store, closeDB = scriptedAccessReviewOperations(&identitySQLState{
		querySteps: []identitySQLQueryStep{{}, itemStep, assignmentStep}, execFailAt: 1, failure: errProfileBindingSQL,
	})
	if _, err := store.ApplyIdentityAccessReviewDecision(t.Context(), expiry); err == nil {
		t.Fatal("expiry assignment failure ignored")
	}
	closeDB()
}

func TestListIdentityAccessReviewItemsEdges(t *testing.T) {
	for _, state := range []*identitySQLState{
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{querySteps: []identitySQLQueryStep{{columns: []string{"first", "second"}, rows: [][]driver.Value{{"a", "b"}}}}},
		{querySteps: []identitySQLQueryStep{{columns: []string{"id"}, nextErr: errProfileBindingSQL}}},
		{queryFailAt: 2, failure: errProfileBindingSQL, querySteps: []identitySQLQueryStep{{columns: []string{"id"}, rows: [][]driver.Value{{"item"}}}}},
	} {
		store, closeDB := scriptedSQLIdentity(state)
		if _, err := store.listIdentityAccessReviewItems(t.Context(), "workspace", "review"); err == nil {
			t.Fatal("item list failure ignored")
		}
		closeDB()
	}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		{columns: []string{"id"}, rows: [][]driver.Value{{"missing"}}},
		{},
	}})
	items, err := store.listIdentityAccessReviewItems(t.Context(), "workspace", "review")
	if err != nil || len(items) != 0 {
		t.Fatalf("missing listed item result=%#v err=%v", items, err)
	}
	closeDB()
}
