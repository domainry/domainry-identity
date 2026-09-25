package entitlement

import (
	"encoding/json"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
)

type persistedEntitlementItem struct {
	identitymodel.IdentityEntitlementBatchItem
	ValidFrom  int64 `json:"valid_from,omitempty"`
	ValidUntil int64 `json:"valid_until,omitempty"`
}

type persistedEntitlementReceipt struct {
	identitymodel.IdentityEntitlementBatchReceipt
	Items     []persistedEntitlementItem `json:"items"`
	CreatedAt int64                      `json:"created_at"`
}

func marshalEntitlementReceipt(value identitymodel.IdentityEntitlementBatchReceipt) ([]byte, error) {
	items := make([]persistedEntitlementItem, len(value.Items))
	for index, item := range value.Items {
		items[index] = persistedEntitlementItem{
			IdentityEntitlementBatchItem: item,
			ValidFrom:                    timevalue.Millis(item.ValidFrom),
			ValidUntil:                   timevalue.Millis(item.ValidUntil),
		}
	}
	return json.Marshal(persistedEntitlementReceipt{
		IdentityEntitlementBatchReceipt: value,
		Items:                           items,
		CreatedAt:                       timevalue.Millis(value.CreatedAt),
	})
}

func unmarshalEntitlementReceipt(raw []byte) (identitymodel.IdentityEntitlementBatchReceipt, error) {
	var stored persistedEntitlementReceipt
	if err := json.Unmarshal(raw, &stored); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	value := stored.IdentityEntitlementBatchReceipt
	value.Items = make([]identitymodel.IdentityEntitlementBatchItem, len(stored.Items))
	for index, item := range stored.Items {
		value.Items[index] = item.IdentityEntitlementBatchItem
		value.Items[index].ValidFrom = timevalue.String(item.ValidFrom)
		value.Items[index].ValidUntil = timevalue.String(item.ValidUntil)
	}
	value.CreatedAt = timevalue.String(stored.CreatedAt)
	return value, nil
}
