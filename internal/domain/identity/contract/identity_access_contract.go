package contract

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const (
	PartyObjectKey                    = "party"
	PersonObjectKey                   = "person"
	OrganizationObjectKey             = "organization"
	IdentityUserObjectKey             = "identity_user"
	IdentityDepartmentObjectKey       = "identity_department"
	IdentityOrganizationUnitObjectKey = "identity_organization_unit"
	IdentityWorkforceProfileObjectKey = "identity_workforce_profile"
)

// IsFoundationObjectKey reports whether objectKey is owned by the Runtime
// foundation and can be referenced without being declared as a business
// metadata object.
func IsFoundationObjectKey(objectKey string) bool {
	switch objectKey {
	case PartyObjectKey, PersonObjectKey, OrganizationObjectKey,
		IdentityUserObjectKey, IdentityDepartmentObjectKey, IdentityOrganizationUnitObjectKey, IdentityWorkforceProfileObjectKey:
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
	FindDepartment(context.Context, string) (identitymodel.IdentityDepartment, bool, error)
	ListDirectoryUsers(context.Context) ([]identitymodel.IdentityUser, error)
	ListDirectoryRoles(context.Context) ([]identitymodel.IdentityRole, error)
	ListDirectoryUserRoleAssignments(context.Context, string) ([]identitymodel.IdentityUserRoleAssignment, error)
}

type IdentityWorkforceDirectory interface {
	ListDirectoryWorkforce(context.Context) ([]identitymodel.IdentityWorkforceDirectoryEntry, error)
}
