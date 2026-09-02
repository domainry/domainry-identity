package contract

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const (
	IdentityUserObjectKey             = "identity_user"
	IdentityOrganizationUnitObjectKey = "identity_organization_unit"
)

// IsFoundationObjectKey reports whether objectKey is owned by the Runtime
// foundation and can be referenced without being declared as a business
// metadata object.
func IsFoundationObjectKey(objectKey string) bool {
	switch objectKey {
	case IdentityUserObjectKey, IdentityOrganizationUnitObjectKey:
		return true
	default:
		return false
	}
}

type IdentityAuthorization interface {
	ResolvePrincipal(context.Context, string) (identitymodel.Principal, error)
	ResolvePrincipalForRole(context.Context, string, string) (identitymodel.Principal, error)
	ResolveEffectivePermissions(context.Context, string) ([]string, error)
	ResolveEffectiveMenus(context.Context, string) ([]identitymodel.IdentityMenu, error)
}

type IdentityDirectory interface {
	FindUser(context.Context, string) (identitymodel.IdentityUser, bool, error)
	FindOrganizationUnit(context.Context, string) (identitymodel.IdentityOrganizationUnit, bool, error)
	ListDirectoryUsers(context.Context) ([]identitymodel.IdentityUser, error)
	ListDirectoryRoles(context.Context) ([]identitymodel.IdentityRole, error)
	ListDirectoryUserRoleAssignments(context.Context, string) ([]identitymodel.IdentityUserRoleAssignment, error)
}
