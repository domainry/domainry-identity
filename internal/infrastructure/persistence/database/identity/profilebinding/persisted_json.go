package profilebinding

import (
	"encoding/json"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
)

type persistedBinding struct {
	identitymodel.IdentityProfileBinding
	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

type persistedBindingReceipt struct {
	identitymodel.IdentityProfileBindingReceipt
	Binding   persistedBinding `json:"binding"`
	CreatedAt int64            `json:"created_at"`
}

func marshalBindingReceipt(value identitymodel.IdentityProfileBindingReceipt) ([]byte, error) {
	return json.Marshal(persistedBindingReceipt{
		IdentityProfileBindingReceipt: value,
		Binding: persistedBinding{
			IdentityProfileBinding: value.Binding,
			CreatedAt:              timevalue.Millis(value.Binding.CreatedAt),
			UpdatedAt:              timevalue.Millis(value.Binding.UpdatedAt),
		},
		CreatedAt: timevalue.Millis(value.CreatedAt),
	})
}

func unmarshalBindingReceipt(raw []byte) (identitymodel.IdentityProfileBindingReceipt, error) {
	var stored persistedBindingReceipt
	if err := json.Unmarshal(raw, &stored); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	value := stored.IdentityProfileBindingReceipt
	value.Binding = stored.Binding.IdentityProfileBinding
	value.Binding.CreatedAt = timevalue.String(stored.Binding.CreatedAt)
	value.Binding.UpdatedAt = timevalue.String(stored.Binding.UpdatedAt)
	value.CreatedAt = timevalue.String(stored.CreatedAt)
	return value, nil
}

type persistedBindingEvent struct {
	identitymodel.IdentityProfileBindingEvent
	CreatedAt int64 `json:"created_at"`
}

func marshalBindingEvent(value identitymodel.IdentityProfileBindingEvent) ([]byte, error) {
	return json.Marshal(persistedBindingEvent{
		IdentityProfileBindingEvent: value,
		CreatedAt:                   timevalue.Millis(value.CreatedAt),
	})
}
