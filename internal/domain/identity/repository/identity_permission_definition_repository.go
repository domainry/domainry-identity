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
	GetIdentityPermissionDefinition(context.Context, string, string) (identitymodel.IdentityPermissionDefinitionRecord, bool, error)
	// SetIdentityPermissionDefinitionEnabled returns true only when an active
	// definition changed state. Missing, retired, and idempotent requests return
	// false without mutating source-owned definition fields.
	SetIdentityPermissionDefinitionEnabled(context.Context, string, string, bool) (bool, error)
	ReconcileIdentityPermissionDefinitions(context.Context, identitymodel.IdentityPermissionReconcileRequest) (identitymodel.IdentityPermissionReconcileReceipt, error)
}
