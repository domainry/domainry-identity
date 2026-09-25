package identity

import (
	"database/sql/driver"
	"fmt"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func validIdentityEntitlementBatchMutation() identitymodel.IdentityEntitlementBatchMutation {
	return identitymodel.IdentityEntitlementBatchMutation{
		WorkspaceID:        "workspace",
		ActorID:            " actor ",
		IdempotencyKey:     " batch-key ",
		RequestFingerprint: " fingerprint ",
		Items: []identitymodel.IdentityEntitlementBatchItem{{
			Operation: identitymodel.IdentityEntitlementOperationGrant,
			UserID:    "user",
			RoleID:    "role",
		}},
		Assignments: []identitymodel.IdentityUserRoleAssignment{{
			UserID: "user", RoleID: "role", Source: "manual", Status: "active",
		}},
	}
}

func scriptedEntitlementOperations(state *identitySQLState) (*SQLIdentityStore, func()) {
	store, closeDB := scriptedSQLIdentity(state)
	store.BindOperationsPersistence()
	return store, closeDB
}

func TestApplyIdentityEntitlementBatchUsesChunkedWrites(t *testing.T) {
	mutation := validIdentityEntitlementBatchMutation()
	mutation.Items = make([]identitymodel.IdentityEntitlementBatchItem, identityUserRoleAssignmentInsertBatchSize+1)
	mutation.Assignments = make([]identitymodel.IdentityUserRoleAssignment, len(mutation.Items))
	for index := range mutation.Items {
		userID := fmt.Sprintf("user-%d", index)
		mutation.Items[index] = identitymodel.IdentityEntitlementBatchItem{Operation: identitymodel.IdentityEntitlementOperationGrant, UserID: userID, RoleID: "role"}
		mutation.Assignments[index] = identitymodel.IdentityUserRoleAssignment{UserID: userID, RoleID: "role", Source: "manual", Status: "active"}
	}
	state := &identitySQLState{}
	store, closeDB := scriptedEntitlementOperations(state)
	defer closeDB()
	if _, err := store.ApplyIdentityEntitlementBatch(t.Context(), mutation); err != nil {
		t.Fatal(err)
	}
	if state.execCount != 3 {
		t.Fatalf("expected two assignment upsert batches and one receipt insert; got %d execs", state.execCount)
	}
}

func identityEntitlementBatchReceiptJSON() string {
	return `{"id":"receipt","workspace_id":"workspace","actor_id":"actor","idempotency_key":"batch-key","request_fingerprint":"fingerprint","items":[],"created_at":"created"}`
}

func TestApplyIdentityEntitlementBatchValidationAndFailureStages(t *testing.T) {
	base := validIdentityEntitlementBatchMutation()
	invalid := []identitymodel.IdentityEntitlementBatchMutation{
		func() identitymodel.IdentityEntitlementBatchMutation {
			value := base
			value.WorkspaceID = ""
			return value
		}(),
		func() identitymodel.IdentityEntitlementBatchMutation { value := base; value.ActorID = ""; return value }(),
		func() identitymodel.IdentityEntitlementBatchMutation {
			value := base
			value.IdempotencyKey = ""
			return value
		}(),
		func() identitymodel.IdentityEntitlementBatchMutation {
			value := base
			value.RequestFingerprint = ""
			return value
		}(),
		func() identitymodel.IdentityEntitlementBatchMutation { value := base; value.Items = nil; return value }(),
		func() identitymodel.IdentityEntitlementBatchMutation {
			value := base
			value.Assignments = nil
			return value
		}(),
	}
	for _, mutation := range invalid {
		store, closeDB := scriptedEntitlementOperations(&identitySQLState{})
		if _, err := store.ApplyIdentityEntitlementBatch(t.Context(), mutation); err == nil {
			t.Fatalf("invalid mutation accepted: %#v", mutation)
		}
		closeDB()
	}

	for _, state := range []*identitySQLState{
		{beginErr: errProfileBindingSQL},
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{execFailAt: 1, failure: errProfileBindingSQL},
		{execFailAt: 2, failure: errProfileBindingSQL},
		{commitErr: errProfileBindingSQL},
	} {
		store, closeDB := scriptedEntitlementOperations(state)
		if _, err := store.ApplyIdentityEntitlementBatch(t.Context(), base); err == nil {
			t.Fatal("entitlement batch pipeline failure ignored")
		}
		closeDB()
	}

	store, closeDB := scriptedEntitlementOperations(&identitySQLState{})
	receipt, err := store.ApplyIdentityEntitlementBatch(t.Context(), base)
	if err != nil || receipt.Replayed || receipt.ActorID != "actor" || receipt.IdempotencyKey != "batch-key" ||
		receipt.RequestFingerprint != "fingerprint" || len(receipt.Items) != 1 {
		t.Fatalf("receipt=%#v error=%v", receipt, err)
	}
	closeDB()
}

func TestGetIdentityEntitlementBatchReceiptRemainingFailures(t *testing.T) {
	store, closeDB := scriptedEntitlementOperations(&identitySQLState{})
	if _, _, err := store.GetIdentityEntitlementBatchReceipt(t.Context(), "", "key"); err == nil {
		t.Fatal("blank workspace accepted")
	}
	closeDB()

	for _, state := range []*identitySQLState{
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{querySteps: []identitySQLQueryStep{{
			columns: []string{"id", "resource_id", "request_fingerprint", "requested_by", "result_json", "created_at", "status"},
			rows:    [][]driver.Value{{"receipt", "receipt", "fingerprint", "actor", "{", int64(1_700_000_000_000), "succeeded"}},
		}}},
	} {
		store, closeDB = scriptedEntitlementOperations(state)
		if _, _, err := store.GetIdentityEntitlementBatchReceipt(t.Context(), "workspace", " key "); err == nil {
			t.Fatal("receipt load failure ignored")
		}
		closeDB()
	}
	store, closeDB = scriptedEntitlementOperations(&identitySQLState{})
	if _, found, err := store.GetIdentityEntitlementBatchReceipt(t.Context(), "workspace", "missing"); err != nil || found {
		t.Fatalf("missing receipt found=%v error=%v", found, err)
	}
	closeDB()
	store, closeDB = scriptedEntitlementOperations(&identitySQLState{querySteps: []identitySQLQueryStep{{
		columns: []string{"id", "resource_id", "request_fingerprint", "requested_by", "result_json", "created_at", "status"},
		rows:    [][]driver.Value{{"receipt", "receipt", "fingerprint", "actor", identityEntitlementBatchReceiptJSON(), int64(1_700_000_000_000), "succeeded"}},
	}}})
	receipt, found, err := store.GetIdentityEntitlementBatchReceipt(t.Context(), "workspace", "batch-key")
	if err != nil || !found || receipt.RequestFingerprint != "fingerprint" {
		t.Fatalf("receipt=%#v found=%v error=%v", receipt, found, err)
	}
	closeDB()
}
