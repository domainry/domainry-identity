package entitlement

import (
	"encoding/json"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestEntitlementReceiptStoresNumericInstants(t *testing.T) {
	instant := time.Date(2026, 9, 25, 10, 30, 0, 0, time.UTC)
	text := instant.Format(time.RFC3339Nano)
	receipt := identitymodel.IdentityEntitlementBatchReceipt{
		CreatedAt: text,
		Items:     []identitymodel.IdentityEntitlementBatchItem{{ValidFrom: text, ValidUntil: text}},
	}
	raw, err := marshalEntitlementReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		CreatedAt int64 `json:"created_at"`
		Items     []struct {
			ValidFrom  int64 `json:"valid_from"`
			ValidUntil int64 `json:"valid_until"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil || stored.CreatedAt != instant.UnixMilli() || len(stored.Items) != 1 || stored.Items[0].ValidFrom != instant.UnixMilli() || stored.Items[0].ValidUntil != instant.UnixMilli() {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	restored, err := unmarshalEntitlementReceipt(raw)
	if err != nil || restored.CreatedAt != text || len(restored.Items) != 1 || restored.Items[0].ValidFrom != text {
		t.Fatalf("restored=%+v err=%v", restored, err)
	}
}
