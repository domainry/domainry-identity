package accessreview

import (
	"encoding/json"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestAccessReviewReceiptStoresNumericInstants(t *testing.T) {
	instant := time.Date(2026, 9, 25, 10, 30, 0, 0, time.UTC)
	text := instant.Format(time.RFC3339Nano)
	receipt := identitymodel.IdentityAccessReviewDecisionReceipt{
		CreatedAt: text,
		Item: identitymodel.IdentityAccessReviewItem{
			LastUsedAt: text, ExpiresAt: text, DecidedAt: text, CreatedAt: text, UpdatedAt: text,
		},
	}
	raw, err := marshalAccessReviewReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		CreatedAt int64 `json:"created_at"`
		Item      struct {
			LastUsedAt int64 `json:"last_used_at"`
			ExpiresAt  int64 `json:"expires_at"`
			DecidedAt  int64 `json:"decided_at"`
			CreatedAt  int64 `json:"created_at"`
			UpdatedAt  int64 `json:"updated_at"`
		} `json:"item"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	for _, got := range []int64{stored.CreatedAt, stored.Item.LastUsedAt, stored.Item.ExpiresAt, stored.Item.DecidedAt, stored.Item.CreatedAt, stored.Item.UpdatedAt} {
		if got != instant.UnixMilli() {
			t.Fatalf("stored=%+v", stored)
		}
	}
	restored, err := unmarshalAccessReviewReceipt(raw)
	if err != nil || restored.CreatedAt != text || restored.Item.ExpiresAt != text {
		t.Fatalf("restored=%+v err=%v", restored, err)
	}
}
