package identity

import (
	"encoding/json"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type persistedHandlerUser struct {
	identitymodel.IdentityUser
	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

type persistedHandlerBinding struct {
	identitymodel.IdentityProfileBinding
	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

type persistedHandlerDeliveryResult struct {
	identitymodel.IdentityHandlerDeliveryResult
	User           persistedHandlerUser     `json:"user"`
	ProfileBinding *persistedHandlerBinding `json:"profile_binding,omitempty"`
}

func marshalHandlerDeliveryResult(value identitymodel.IdentityHandlerDeliveryResult) ([]byte, error) {
	stored := persistedHandlerDeliveryResult{
		IdentityHandlerDeliveryResult: value,
		User: persistedHandlerUser{
			IdentityUser: value.User,
			CreatedAt:    timeMillis(value.User.CreatedAt),
			UpdatedAt:    timeMillis(value.User.UpdatedAt),
		},
	}
	if value.ProfileBinding != nil {
		stored.ProfileBinding = &persistedHandlerBinding{
			IdentityProfileBinding: *value.ProfileBinding,
			CreatedAt:              timeMillis(value.ProfileBinding.CreatedAt),
			UpdatedAt:              timeMillis(value.ProfileBinding.UpdatedAt),
		}
	}
	return json.Marshal(stored)
}

func unmarshalHandlerDeliveryResult(raw []byte) (identitymodel.IdentityHandlerDeliveryResult, error) {
	var stored persistedHandlerDeliveryResult
	if err := json.Unmarshal(raw, &stored); err != nil {
		return identitymodel.IdentityHandlerDeliveryResult{}, err
	}
	value := stored.IdentityHandlerDeliveryResult
	value.User = stored.User.IdentityUser
	value.User.CreatedAt = timeString(stored.User.CreatedAt)
	value.User.UpdatedAt = timeString(stored.User.UpdatedAt)
	if stored.ProfileBinding != nil {
		binding := stored.ProfileBinding.IdentityProfileBinding
		binding.CreatedAt = timeString(stored.ProfileBinding.CreatedAt)
		binding.UpdatedAt = timeString(stored.ProfileBinding.UpdatedAt)
		value.ProfileBinding = &binding
	}
	return value, nil
}
