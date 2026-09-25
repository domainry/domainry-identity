package identity

import (
	"encoding/json"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestHandlerDeliveryResultStoresNumericInstants(t *testing.T) {
	instant := time.Date(2026, 9, 25, 10, 30, 0, 0, time.UTC)
	value := instant.Format(time.RFC3339Nano)
	result := identitymodel.IdentityHandlerDeliveryResult{
		User: identitymodel.IdentityUser{CreatedAt: value, UpdatedAt: value},
		ProfileBinding: &identitymodel.IdentityProfileBinding{
			CreatedAt: value, UpdatedAt: value,
		},
	}
	raw, err := marshalHandlerDeliveryResult(result)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		User struct {
			CreatedAt int64 `json:"created_at"`
			UpdatedAt int64 `json:"updated_at"`
		} `json:"user"`
		ProfileBinding struct {
			CreatedAt int64 `json:"created_at"`
			UpdatedAt int64 `json:"updated_at"`
		} `json:"profile_binding"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil || stored.User.CreatedAt != instant.UnixMilli() || stored.User.UpdatedAt != instant.UnixMilli() || stored.ProfileBinding.CreatedAt != instant.UnixMilli() || stored.ProfileBinding.UpdatedAt != instant.UnixMilli() {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	restored, err := unmarshalHandlerDeliveryResult(raw)
	if err != nil || restored.User.CreatedAt != value || restored.ProfileBinding == nil || restored.ProfileBinding.UpdatedAt != value {
		t.Fatalf("restored=%+v err=%v", restored, err)
	}
}
