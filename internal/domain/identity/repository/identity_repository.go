package repository

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type IdentityRepository interface {
	ListIdentityOrganizationUnits(context.Context, string) ([]identitymodel.IdentityOrganizationUnit, error)
	UpsertIdentityOrganizationUnit(context.Context, string, identitymodel.IdentityOrganizationUnit) error
	UpsertIdentityOrganizationUnitsAtomically(context.Context, string, []identitymodel.IdentityOrganizationUnit) error
	ListIdentityUsers(context.Context, string) ([]identitymodel.IdentityUser, error)
	ListIdentityProfileBindingsByUser(context.Context, string, string) ([]identitymodel.IdentityProfileBinding, error)
	GetIdentityUser(context.Context, string, string) (identitymodel.IdentityUser, bool, error)
	UpsertIdentityUser(context.Context, string, identitymodel.IdentityUser) error
	UpsertIdentityUsersAtomically(context.Context, string, []identitymodel.IdentityUser) error
	RemoveIdentityUser(context.Context, string, string) error
	SetIdentityUserStatus(context.Context, string, string, identitymodel.IdentityStatus) error
	ListIdentityRoles(context.Context, string) ([]identitymodel.IdentityRole, error)
	UpsertIdentityRole(context.Context, string, identitymodel.IdentityRole) error
	RemoveIdentityRole(context.Context, string, string) error
	AssignIdentityUserRole(context.Context, string, identitymodel.IdentityUserRoleAssignment) error
	RemoveIdentityUserRole(context.Context, string, string, string) error
	ListIdentityUserRoleAssignments(context.Context, string, string) ([]identitymodel.IdentityUserRoleAssignment, error)
	CreateIdentityRoleRequest(context.Context, string, identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error)
	ListIdentityRoleRequests(context.Context, string, string, string) ([]identitymodel.IdentityRoleRequest, error)
	UpdateIdentityRoleRequest(context.Context, string, identitymodel.IdentityRoleRequest) error
	ListIdentityMenus(context.Context, string) ([]identitymodel.IdentityMenu, error)
	UpsertIdentityMenu(context.Context, string, identitymodel.IdentityMenu) error
	RemoveIdentityMenu(context.Context, string, string) error
	SetIdentityRoleMenus(context.Context, string, string, []string) error
	ListIdentityRoleMenuAssignments(context.Context, string, string) ([]identitymodel.IdentityRoleMenuAssignment, error)
}

type IdentityUserLookupRepository interface {
	GetIdentityUser(context.Context, string, string) (identitymodel.IdentityUser, bool, error)
}

// IdentityUserDataScopeRepository is the storage-bound user projection
// capability. Implementations apply the compiled filter in the database (or
// in the in-memory repository itself for tests); callers must not load an
// unscoped page and filter it in the application layer.
type IdentityUserDataScopeRepository interface {
	ListIdentityUsersWithinDataScope(context.Context, string, identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUser, error)
	GetIdentityUserWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityUser, bool, error)
}

// IdentityOrganizationUnitDataScopeRepository applies organization scopes to
// the unit's natural identity column. Organization units are not user-owned:
// OwnerUserIDs are deliberately ignored and an owner-only grant matches no
// units.
type IdentityOrganizationUnitDataScopeRepository interface {
	ListIdentityOrganizationUnitsWithinDataScope(context.Context, string, identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityOrganizationUnit, error)
	GetIdentityOrganizationUnitWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityOrganizationUnit, bool, error)
}

type IdentityOrganizationUnitDataScopeMutationRepository interface {
	UpsertIdentityOrganizationUnitsWithinDataScopeAtomically(context.Context, string, []identitymodel.IdentityOrganizationUnit, identitymodel.IdentityDataScopeFilter) (bool, error)
}

type IdentityUserDataScopeSearchRepository interface {
	SearchIdentityUsersWithinDataScope(context.Context, string, identitymodel.IdentityListQuery, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityUserPage, error)
}

// IdentityUserRoleAssignmentDataScopeRepository scopes the assignment
// relation through its target user. Role definitions are workspace templates;
// they deliberately do not carry organization ownership of their own.
type IdentityUserRoleAssignmentDataScopeReader interface {
	ListIdentityUserRoleAssignmentsWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUserRoleAssignment, error)
}

type IdentityUserRoleAssignmentDataScopeRepository interface {
	IdentityUserRoleAssignmentDataScopeReader
	AssignIdentityUserRoleWithinDataScope(context.Context, string, identitymodel.IdentityUserRoleAssignment, identitymodel.IdentityDataScopeFilter) (bool, error)
	RemoveIdentityUserRoleWithinDataScope(context.Context, string, string, string, identitymodel.IdentityDataScopeFilter) (bool, error)
}

type IdentityUserCreateRepository interface {
	CreateIdentityUser(context.Context, string, identitymodel.IdentityUser) error
}

// IdentityUserDataScopeMutationRepository repeats the same compiled data-scope
// predicate on the final write. A false result means at least one candidate did
// not exist inside that scope; implementations must leave the whole mutation
// unchanged in that case.
type IdentityUserDataScopeMutationRepository interface {
	UpdateIdentityUsersWithinDataScopeAtomically(context.Context, string, []identitymodel.IdentityUser, identitymodel.IdentityDataScopeFilter) (bool, error)
	RemoveIdentityUserWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (bool, error)
	SetIdentityUserStatusWithinDataScope(context.Context, string, string, identitymodel.IdentityStatus, identitymodel.IdentityDataScopeFilter) (bool, error)
}

type IdentityUserProjectionFactsRepository interface {
	ListIdentityUserProjectionFacts(context.Context, string, []string) (identitymodel.IdentityUserProjectionFacts, error)
}

type IdentityAccountDisableRepository interface {
	DisableIdentityAccount(context.Context, string, string) (int, error)
}

type IdentityAccountDataScopeDisableRepository interface {
	DisableIdentityAccountWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (int, bool, error)
}

type IdentityRoleRequestDecisionRepository interface {
	ApplyIdentityRoleRequestDecision(context.Context, string, identitymodel.IdentityRoleRequest, []identitymodel.IdentityUserRoleAssignment, string) error
}

type IdentityUserRoleReconcileRepository interface {
	UpsertIdentityUserWithRoleAssignmentsAtomically(context.Context, string, identitymodel.IdentityUser, []identitymodel.IdentityUserRoleAssignment) error
}

type IdentityUserRoleDataScopeReconcileRepository interface {
	UpsertIdentityUserWithRoleAssignmentsWithinDataScopeAtomically(context.Context, string, identitymodel.IdentityUser, []identitymodel.IdentityUserRoleAssignment, identitymodel.IdentityDataScopeFilter) (bool, error)
}

// IdentityRoleRequestDataScopeRepository scopes requests through the persisted
// target user and repeats that predicate inside decision transactions.
type IdentityRoleRequestDataScopeRepository interface {
	ListIdentityRoleRequestsWithinDataScope(context.Context, string, string, string, identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityRoleRequest, error)
	ApplyIdentityRoleRequestDecisionWithinDataScope(context.Context, string, identitymodel.IdentityRoleRequest, []identitymodel.IdentityUserRoleAssignment, string, identitymodel.IdentityDataScopeFilter) (bool, error)
}

type IdentityEntitlementBatchRepository interface {
	GetIdentityEntitlementBatchReceipt(context.Context, string, string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error)
	ApplyIdentityEntitlementBatch(context.Context, identitymodel.IdentityEntitlementBatchMutation) (identitymodel.IdentityEntitlementBatchReceipt, error)
}

type IdentityEntitlementBatchDataScopeRepository interface {
	GetIdentityEntitlementBatchReceiptWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error)
	ApplyIdentityEntitlementBatchWithinDataScope(context.Context, identitymodel.IdentityEntitlementBatchMutation, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error)
}

type IdentityAccessReviewRepository interface {
	CreateIdentityAccessReview(context.Context, identitymodel.IdentityAccessReview) error
	ListIdentityAccessReviews(context.Context, string, string) ([]identitymodel.IdentityAccessReview, error)
	GetIdentityAccessReviewItem(context.Context, string, string) (identitymodel.IdentityAccessReviewItem, bool, error)
	GetIdentityAccessReviewDecisionReceipt(context.Context, string, string, string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error)
	ApplyIdentityAccessReviewDecision(context.Context, identitymodel.IdentityAccessReviewDecisionMutation) (identitymodel.IdentityAccessReviewDecisionReceipt, error)
}

// IdentityAccessReviewDataScopeRepository treats every review item as a user
// entitlement and therefore scopes it through the item's persisted user.
type IdentityAccessReviewDataScopeRepository interface {
	CreateIdentityAccessReviewWithinDataScope(context.Context, identitymodel.IdentityAccessReview, identitymodel.IdentityDataScopeFilter) (bool, error)
	ListIdentityAccessReviewsWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityAccessReview, error)
	GetIdentityAccessReviewItemWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewItem, bool, error)
	GetIdentityAccessReviewDecisionReceiptWithinDataScope(context.Context, string, string, string, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error)
	ApplyIdentityAccessReviewDecisionWithinDataScope(context.Context, identitymodel.IdentityAccessReviewDecisionMutation, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error)
}

// IdentityUserLocaleRepository is the narrow compare-and-swap persistence
// capability consumed only by current-user locale self-service.
type IdentityUserLocaleRepository interface {
	UpdateIdentityUserLocale(context.Context, string, string, string, int64) (identitymodel.IdentityUser, bool, error)
}

// IdentityTransactionManager executes one application-owned operation inside
// Identity's transaction, or joins the host transaction already carried by
// the adapter-private context. It never exposes commit or rollback to callers.
type IdentityTransactionManager interface {
	WithinIdentityTransaction(context.Context, func(context.Context) error) error
}

// IdentityHandlerDeliveryRepository is the narrow persistence port for the
// generated-handler delivery aggregate. Implementations require an active
// Identity transaction and persist the top-level replay receipt with every
// owned effect.
type IdentityHandlerDeliveryRepository interface {
	GetIdentityHandlerDeliveryReceipt(context.Context, string, string) (identitymodel.IdentityHandlerDeliveryReceipt, bool, error)
	ExecuteIdentityHandlerDelivery(context.Context, identitymodel.IdentityHandlerDeliveryMutation) (identitymodel.IdentityHandlerDeliveryReceipt, error)
}

// IdentityStoreOrganizationDeliveryRepository owns only concurrency evidence
// and the atomic StoreOrganization mutation. Organization facts remain in the
// canonical Identity organization aggregate; the state record stores a CAS
// version and fingerprint, not a duplicate organization projection.
type IdentityStoreOrganizationDeliveryRepository interface {
	GetIdentityStoreOrganizationDeliveryReceipt(context.Context, string, string) (identitymodel.IdentityStoreOrganizationDeliveryReceipt, bool, error)
	GetIdentityStoreOrganizationState(context.Context, string, string) (identitymodel.IdentityStoreOrganizationState, bool, error)
	ListIdentityStoreOrganizationsPage(context.Context, string, identitymodel.IdentityDataScopeFilter, string, int) ([]identitymodel.IdentityStoreOrganization, error)
	ExecuteIdentityStoreOrganizationDelivery(context.Context, identitymodel.IdentityStoreOrganizationDeliveryMutation) (identitymodel.IdentityStoreOrganizationDeliveryReceipt, error)
}

// IdentityWorkspaceUsageRepository returns grouped account dimensions for a
// bounded, authority-selected Workspace page in one query. It never loads
// user projections or performs per-Workspace reads.
type IdentityWorkspaceUsageRepository interface {
	CountIdentityWorkspaceUsage(context.Context, []string) ([]identitymodel.IdentityWorkspaceUsageGroup, error)
	CountIdentityWorkspaceActiveHumanAccountsWithActiveRole(context.Context, []string) ([]identitymodel.IdentityWorkspaceActiveHumanRoleCount, error)
}

type IdentityRoleAuthorizationCommit struct {
	Role             identitymodel.IdentityRole
	Permissions      *[]identitymodel.RolePermission
	FieldPermissions *[]identitymodel.IdentityFieldPermission
}

// IdentityAtomicMutationRepository owns multi-table Identity mutations that
// must not expose a partially deleted menu tree.
type IdentityAtomicMutationRepository interface {
	RemoveIdentityMenusAtomically(context.Context, string, []identitymodel.IdentityMenu) error
}

// IdentitySeedRepository is the Identity aggregate persistence contract needed
// while materializing a manifest-owned bootstrap graph.
type IdentitySeedRepository interface {
	ListIdentityRoles(context.Context, string) ([]identitymodel.IdentityRole, error)
	UpsertIdentityRole(context.Context, string, identitymodel.IdentityRole) error
	ApplyIdentityBootstrapAtomically(context.Context, string, []identitymodel.IdentityOrganizationUnit, []identitymodel.IdentityUser, []identitymodel.IdentityUserRoleAssignment) error
	UpsertIdentityUser(context.Context, string, identitymodel.IdentityUser) error
	AssignIdentityUserRole(context.Context, string, identitymodel.IdentityUserRoleAssignment) error
	ListIdentityMenus(context.Context, string) ([]identitymodel.IdentityMenu, error)
	UpsertIdentityMenu(context.Context, string, identitymodel.IdentityMenu) error
	RemoveIdentityMenu(context.Context, string, string) error
	SetIdentityRoleMenus(context.Context, string, string, []string) error
	ListIdentityRoleMenuAssignments(context.Context, string, string) ([]identitymodel.IdentityRoleMenuAssignment, error)
}
