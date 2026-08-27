package contract

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// AuthIdentityPort is the consumer-owned Identity boundary required by Auth.
type AuthIdentityPort interface {
	AssignUserRole(context.Context, identitymodel.IdentityUserRoleAssignment) error
	ListRoles(context.Context) ([]identitymodel.IdentityRole, error)
	UpsertUser(context.Context, identitymodel.IdentityUser) error
	UserByID(context.Context, string) (identitymodel.IdentityUser, bool, error)
	UserByLogin(context.Context, string) (identitymodel.IdentityUser, bool, error)
	ActiveRolesForUser(context.Context, string) ([]identitymodel.IdentityRole, error)
	PublishedRoleDefinition(context.Context, string) (identitymodel.RoleSchema, bool)
	ResolveEffectivePermissions(context.Context, string) ([]string, error)
	ResolvePrincipal(context.Context, string) (identitymodel.Principal, error)
}

type AuthLocaleIdentityPort interface {
	UpdateUserLocale(context.Context, string, string, string, int64) (identitymodel.IdentityUser, error)
}

type AuthAuthorization interface {
	ResolveEffectivePermissions(context.Context, string) ([]string, error)
	ResolvePrincipal(context.Context, string) (identitymodel.Principal, error)
}
