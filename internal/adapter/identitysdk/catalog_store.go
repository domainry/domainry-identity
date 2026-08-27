package identitysdkadapter

import (
	"context"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type CatalogPersistence interface {
	Save(context.Context, identitysdk.AuthorizationCatalog, identitysdk.CatalogReceipt) error
	Load(context.Context, identitysdk.ApplicationRef) (identitysdk.AuthorizationCatalog, identitysdk.CatalogReceipt, bool, error)
	LoadRevision(context.Context, identitysdk.ApplicationRef, identitysdk.CatalogRevision) (identitysdk.AuthorizationCatalog, identitysdk.CatalogReceipt, bool, error)
}
