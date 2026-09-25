package accessreview

import (
	"encoding/json"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
)

type persistedAccessReviewItem struct {
	identitymodel.IdentityAccessReviewItem
	LastUsedAt int64 `json:"last_used_at,omitempty"`
	ExpiresAt  int64 `json:"expires_at,omitempty"`
	DecidedAt  int64 `json:"decided_at,omitempty"`
	CreatedAt  int64 `json:"created_at"`
	UpdatedAt  int64 `json:"updated_at"`
}

type persistedAccessReviewReceipt struct {
	identitymodel.IdentityAccessReviewDecisionReceipt
	Item      persistedAccessReviewItem `json:"item"`
	CreatedAt int64                     `json:"created_at"`
}

func marshalAccessReviewReceipt(value identitymodel.IdentityAccessReviewDecisionReceipt) ([]byte, error) {
	return json.Marshal(persistedAccessReviewReceipt{
		IdentityAccessReviewDecisionReceipt: value,
		Item: persistedAccessReviewItem{
			IdentityAccessReviewItem: value.Item,
			LastUsedAt:               timevalue.Millis(value.Item.LastUsedAt),
			ExpiresAt:                timevalue.Millis(value.Item.ExpiresAt),
			DecidedAt:                timevalue.Millis(value.Item.DecidedAt),
			CreatedAt:                timevalue.Millis(value.Item.CreatedAt),
			UpdatedAt:                timevalue.Millis(value.Item.UpdatedAt),
		},
		CreatedAt: timevalue.Millis(value.CreatedAt),
	})
}

func unmarshalAccessReviewReceipt(raw []byte) (identitymodel.IdentityAccessReviewDecisionReceipt, error) {
	var stored persistedAccessReviewReceipt
	if err := json.Unmarshal(raw, &stored); err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	value := stored.IdentityAccessReviewDecisionReceipt
	value.Item = stored.Item.IdentityAccessReviewItem
	value.Item.LastUsedAt = timevalue.String(stored.Item.LastUsedAt)
	value.Item.ExpiresAt = timevalue.String(stored.Item.ExpiresAt)
	value.Item.DecidedAt = timevalue.String(stored.Item.DecidedAt)
	value.Item.CreatedAt = timevalue.String(stored.Item.CreatedAt)
	value.Item.UpdatedAt = timevalue.String(stored.Item.UpdatedAt)
	value.CreatedAt = timevalue.String(stored.CreatedAt)
	return value, nil
}
