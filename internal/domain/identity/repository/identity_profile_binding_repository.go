package repository

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type IdentityProfileBindingRepository interface {
	GetIdentityProfileBinding(context.Context, string, string, string) (identitymodel.IdentityProfileBinding, bool, error)
	GetIdentityProfileBindingByKey(context.Context, string, string, string) (identitymodel.IdentityProfileBinding, bool, error)
	GetIdentityProfileBindingReceipt(context.Context, identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, bool, error)
	ExecuteIdentityProfileBindingMutation(context.Context, identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, error)
	ListIdentityProfileBindingEvents(context.Context, string, string, string) ([]identitymodel.IdentityProfileBindingEvent, error)
}
