package contract

import (
	"context"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

const (
	IdentityUserObjectKey                                = "identity_user"
	IdentityOrganizationUnitObjectKey                    = "identity_organization_unit"
	IdentityUsersResource                                = "identity.users"
	IdentityRolesResource                                = "identity.roles"
	IdentityUserRoleAssignmentsResource                  = "identity.user_role_assignments"
	IdentityUserRoleAssignmentsListPermission            = "identity.user_role_assignments.list"
	IdentityUserRoleAssignmentsSearchPermission          = "identity.user_role_assignments.search"
	IdentityUserRoleAssignmentsAssignableRolesPermission = "identity.user_role_assignments.assignable_roles"
	IdentityUserRoleAssignmentsAccountUpdatePermission   = "identity.user_role_assignments.account_and_roles_update"
	IdentityUserRoleAssignmentsVersionsPermission        = "identity.user_role_assignments.versions"
	IdentityUserRoleAssignmentsAssignPermission          = "identity.user_role_assignments.assign"
	IdentityUserRoleAssignmentsValidatePermission        = "identity.user_role_assignments.validate"
	IdentityUserRoleAssignmentsRevokePermission          = "identity.user_role_assignments.revoke"
	IdentityRoleRequestsListPermission                   = "identity.role_requests.list"
	IdentityRoleRequestsApprovePermission                = "identity.role_requests.approve"
	IdentityRoleRequestsRejectPermission                 = "identity.role_requests.reject"
	IdentityAccessReviewsCreatePermission                = "identity.access_reviews.create"
	IdentityAccessReviewsListPermission                  = "identity.access_reviews.list"
	IdentityAccessReviewItemsDecidePermission            = "identity.access_review_items.decide"
	IdentityUsersSecurityGetPermission                   = "identity.users.security_get"
	IdentityUsersUnlockPermission                        = "identity.users.unlock"
	IdentityUsersMFARevokePermission                     = "identity.users.mfa_revoke"
	IdentityUsersVersionsPermission                      = "identity.users.versions"
	IdentityUsersCreatePermission                        = "identity.users.create"
	IdentityUsersGetPermission                           = "identity.users.get"
	IdentityUsersUpdatePermission                        = "identity.users.update"
	IdentityUsersDisablePermission                       = "identity.users.disable"
	IdentityHandlerDeliveryCreatePermission              = "identity.handler_delivery.create"
	IdentityHandlerDeliveryUpdatePermission              = "identity.handler_delivery.update"
	IdentityHandlerDeliveryDisablePermission             = "identity.handler_delivery.disable"
	IdentityHandlerDeliveryResolvePermission             = "identity.handler_delivery.resolve"
	IdentityStoreOrganizationDeliveryCreatePermission    = "identity.store_organization_delivery.create"
	IdentityStoreOrganizationDeliveryRenamePermission    = "identity.store_organization_delivery.rename"
	IdentityStoreOrganizationDeliveryDisablePermission   = "identity.store_organization_delivery.disable"
	IdentityStoreOrganizationDeliveryResolvePermission   = "identity.store_organization_delivery.resolve"
	IdentityStoreOrganizationDeliveryListPermission      = "identity.store_organization_delivery.list"
	IdentityOrganizationUnitsVersionsPermission          = "identity.organization_units.versions"
	IdentityEntitlementsBatchPermission                  = "identity.entitlements.batch"
)

type IdentityResourceFacts struct {
	RecordID    string
	OwnerUserID string
	OwnerOrgID  string
}

// IdentityPermissionDataScopeFilter compiles only trusted principal state and
// the exact Permission grant. Callers may use a client ID only as a candidate
// in a repository query that also applies this filter.
func IdentityPermissionDataScopeFilter(principal identitymodel.Principal, permissionKey string) identitymodel.IdentityDataScopeFilter {
	if !principal.Known {
		return identitymodel.IdentityDataScopeFilter{}
	}
	permissions := identitymodel.RolePermissionsForKey(principal.Role.Permissions, strings.TrimSpace(permissionKey))
	filter := identitymodel.IdentityDataScopeFilter{}
	for _, permission := range permissions {
		switch permission.DataScope {
		case identitymodel.IdentityDataScopeAll:
			return identitymodel.IdentityDataScopeFilter{Unrestricted: true}
		case identitymodel.IdentityDataScopeOwner:
			filter.OwnerUserIDs = append(filter.OwnerUserIDs, principal.UserID)
		case identitymodel.IdentityDataScopeOrg:
			filter.OwnerOrgIDs = append(filter.OwnerOrgIDs, principal.OrgID)
		case identitymodel.IdentityDataScopeOrgChild:
			filter.OwnerOrgIDs = append(filter.OwnerOrgIDs, principal.OrgScopeIDs...)
		case identitymodel.IdentityDataScopeTargetOrg:
			filter.OwnerOrgIDs = append(filter.OwnerOrgIDs, principal.SupportOrgScopeIDs...)
		}
	}
	return filter.Normalized()
}

// IdentityPermissionDataScopeAllows applies the exact Permission grant's
// DataScope to one known record. Missing grants and missing facts deny.
func IdentityPermissionDataScopeAllows(principal identitymodel.Principal, permissionKey string, facts IdentityResourceFacts) bool {
	filter := IdentityPermissionDataScopeFilter(principal, permissionKey)
	if filter.Unrestricted {
		return true
	}
	return identityStringContains(filter.OwnerUserIDs, facts.OwnerUserID) || identityStringContains(filter.OwnerOrgIDs, facts.OwnerOrgID)
}

func identityStringContains(values []string, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == expected {
			return true
		}
	}
	return false
}

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

type IdentityProjection interface {
	FindUser(context.Context, string) (identitymodel.IdentityUser, bool, error)
	FindOrganizationUnit(context.Context, string) (identitymodel.IdentityOrganizationUnit, bool, error)
	ListProjectionUsers(context.Context) ([]identitymodel.IdentityUser, error)
	ListProjectionRoles(context.Context) ([]identitymodel.IdentityRole, error)
	ListProjectionUserRoleAssignments(context.Context, string) ([]identitymodel.IdentityUserRoleAssignment, error)
}
