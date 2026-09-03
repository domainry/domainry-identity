package contract

import "testing"

func TestObjectLedgerIntegrityIsBackendOwned(t *testing.T) {
	payload := metadataObjectPayloadSchema()
	ledger := payload.Properties["ledger_policy"]
	if _, exists := ledger.Properties["integrity"]; exists {
		t.Fatal("ledger integrity leaked into the model-facing authoring schema")
	}
}
