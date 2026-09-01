package repository

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// IdentityPermissionDefinitionRepository is deliberately separate from the
// broad IdentityRepository so existing domain test doubles do not become a
// second permission-definition implementation.
type IdentityPermissionDefinitionRepository interface {
	ListIdentityPermissionDefinitions(context.Context, string) ([]identitymodel.IdentityPermissionDefinitionRecord, error)
	ReconcileIdentityPermissionDefinitions(context.Context, identitymodel.IdentityPermissionReconcileRequest) (identitymodel.IdentityPermissionReconcileReceipt, error)
}
