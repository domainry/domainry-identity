package identity

import (
	"database/sql/driver"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func validWorkforceTransferBatchMutation() identitymodel.IdentityWorkforceTransferBatchMutation {
	return identitymodel.IdentityWorkforceTransferBatchMutation{
		WorkspaceID:        "workspace",
		ActorID:            " actor ",
		IdempotencyKey:     " batch-key ",
		RequestFingerprint: " fingerprint ",
		Items: []identitymodel.IdentityWorkforceTransferBatchItem{{
			ProfileID: "profile",
			Assignment: identitymodel.IdentityWorkforceAssignment{
				ID: "assignment", WorkforceProfileID: "profile", OrganizationUnitID: "unit",
			},
		}},
		Mutations: []identitymodel.IdentityWorkforceLifecycleMutation{{}},
	}
}

func workforceTransferBatchReceiptJSON() string {
	return `{"id":"receipt","workspace_id":"workspace","actor_id":"actor","idempotency_key":"batch-key","request_fingerprint":"fingerprint","items":[],"created_at":"created"}`
}

func TestApplyIdentityWorkforceTransferBatchValidationAndPipelineFailures(t *testing.T) {
	base := validWorkforceTransferBatchMutation()
	invalid := []identitymodel.IdentityWorkforceTransferBatchMutation{
		func() identitymodel.IdentityWorkforceTransferBatchMutation {
			value := base
			value.WorkspaceID = ""
			return value
		}(),
		func() identitymodel.IdentityWorkforceTransferBatchMutation {
			value := base
			value.ActorID = ""
			return value
		}(),
		func() identitymodel.IdentityWorkforceTransferBatchMutation {
			value := base
			value.IdempotencyKey = ""
			return value
		}(),
		func() identitymodel.IdentityWorkforceTransferBatchMutation {
			value := base
			value.RequestFingerprint = ""
			return value
		}(),
		func() identitymodel.IdentityWorkforceTransferBatchMutation {
			value := base
			value.Items = nil
			return value
		}(),
		func() identitymodel.IdentityWorkforceTransferBatchMutation {
			value := base
			value.Mutations = nil
			return value
		}(),
	}
	for _, mutation := range invalid {
		store, closeDB := scriptedSQLIdentity(&identitySQLState{})
		if _, err := store.ApplyIdentityWorkforceTransferBatch(t.Context(), mutation); err == nil {
			t.Fatalf("invalid mutation accepted: %#v", mutation)
		}
		closeDB()
	}

	for _, state := range []*identitySQLState{
		{beginErr: errProfileBindingSQL},
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{execFailAt: 1, failure: errProfileBindingSQL},
		{commitErr: errProfileBindingSQL},
	} {
		store, closeDB := scriptedSQLIdentity(state)
		if _, err := store.ApplyIdentityWorkforceTransferBatch(t.Context(), base); err == nil {
			t.Fatal("batch pipeline failure ignored")
		}
		closeDB()
	}

	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	receipt, err := store.ApplyIdentityWorkforceTransferBatch(t.Context(), base)
	if err != nil || receipt.Replayed || receipt.ActorID != "actor" || receipt.IdempotencyKey != "batch-key" ||
		receipt.RequestFingerprint != "fingerprint" || len(receipt.Items) != 1 {
		t.Fatalf("receipt=%#v error=%v", receipt, err)
	}
	closeDB()
}

func TestApplyIdentityWorkforceTransferBatchReplayMatrix(t *testing.T) {
	base := validWorkforceTransferBatchMutation()
	for _, fingerprint := range []string{"other", "fingerprint"} {
		store, closeDB := scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{
			columns: []string{"result_json", "request_fingerprint"},
			rows:    [][]driver.Value{{workforceTransferBatchReceiptJSON(), fingerprint}},
		}}})
		receipt, err := store.ApplyIdentityWorkforceTransferBatch(t.Context(), base)
		if fingerprint == "other" && apperror.CodeOf(err) != "backend.idempotency_key_reused" {
			t.Fatalf("key reuse error=%v", err)
		}
		if fingerprint == "fingerprint" && (err != nil || !receipt.Replayed || receipt.ID != "receipt") {
			t.Fatalf("replay=%#v error=%v", receipt, err)
		}
		closeDB()
	}
}

func TestGetIdentityWorkforceTransferBatchReceiptRemainingFailures(t *testing.T) {
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if _, _, err := store.GetIdentityWorkforceTransferBatchReceipt(t.Context(), "", "key"); err == nil {
		t.Fatal("blank workspace accepted")
	}
	closeDB()
	for _, state := range []*identitySQLState{
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{querySteps: []identitySQLQueryStep{{
			columns: []string{"result_json", "request_fingerprint"},
			rows:    [][]driver.Value{{"{", "fingerprint"}},
		}}},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if _, _, err := store.GetIdentityWorkforceTransferBatchReceipt(t.Context(), "workspace", " key "); err == nil {
			t.Fatal("receipt load failure ignored")
		}
		closeDB()
	}
	store, closeDB = scriptedSQLIdentity(&identitySQLState{})
	if _, found, err := store.GetIdentityWorkforceTransferBatchReceipt(t.Context(), "workspace", "missing"); err != nil || found {
		t.Fatalf("missing receipt found=%v error=%v", found, err)
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{
		columns: []string{"result_json", "request_fingerprint"},
		rows:    [][]driver.Value{{workforceTransferBatchReceiptJSON(), "fingerprint"}},
	}}})
	receipt, found, err := store.GetIdentityWorkforceTransferBatchReceipt(t.Context(), "workspace", "key")
	if err != nil || !found || receipt.RequestFingerprint != "fingerprint" {
		t.Fatalf("receipt=%#v found=%v error=%v", receipt, found, err)
	}
	closeDB()
}
