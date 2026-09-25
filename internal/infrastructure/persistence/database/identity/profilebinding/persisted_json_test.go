package profilebinding

import (
	"encoding/json"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestBindingReceiptAndEventStoreNumericInstants(t *testing.T) {
	instant := time.Date(2026, 9, 25, 18, 30, 0, 0, time.FixedZone("local", 8*3600))
	local := instant.Format(time.RFC3339Nano)
	receipt := identitymodel.IdentityProfileBindingReceipt{
		CreatedAt: local,
		Binding:   identitymodel.IdentityProfileBinding{CreatedAt: local, UpdatedAt: local},
	}
	raw, err := marshalBindingReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		CreatedAt int64 `json:"created_at"`
		Binding   struct {
			CreatedAt int64 `json:"created_at"`
			UpdatedAt int64 `json:"updated_at"`
		} `json:"binding"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.CreatedAt != instant.UnixMilli() || stored.Binding.CreatedAt != instant.UnixMilli() || stored.Binding.UpdatedAt != instant.UnixMilli() {
		t.Fatalf("stored=%+v", stored)
	}
	restored, err := unmarshalBindingReceipt(raw)
	if err != nil || restored.CreatedAt != instant.UTC().Format(time.RFC3339Nano) || restored.Binding.UpdatedAt != restored.CreatedAt {
		t.Fatalf("restored=%+v err=%v", restored, err)
	}
	eventRaw, err := marshalBindingEvent(identitymodel.IdentityProfileBindingEvent{CreatedAt: local})
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		CreatedAt int64 `json:"created_at"`
	}
	if err := json.Unmarshal(eventRaw, &event); err != nil || event.CreatedAt != instant.UnixMilli() {
		t.Fatalf("event=%+v err=%v", event, err)
	}
}
