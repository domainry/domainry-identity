package repository

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type IdentityRepository interface {
	ListIdentityDepartments(context.Context, string) ([]identitymodel.IdentityDepartment, error)
	UpsertIdentityDepartment(context.Context, string, identitymodel.IdentityDepartment) error
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

type IdentityWorkforceRepository interface {
	ListIdentityWorkforceProfiles(context.Context, string) ([]identitymodel.IdentityWorkforceProfile, error)
	GetIdentityWorkforceProfile(context.Context, string, string) (identitymodel.IdentityWorkforceProfile, bool, error)
	UpsertIdentityWorkforceProfile(context.Context, string, identitymodel.IdentityWorkforceProfile) error
	ListIdentityWorkforceAssignments(context.Context, string, string) ([]identitymodel.IdentityWorkforceAssignment, error)
	GetIdentityWorkforceAssignment(context.Context, string, string) (identitymodel.IdentityWorkforceAssignment, bool, error)
	UpsertIdentityWorkforceAssignment(context.Context, string, identitymodel.IdentityWorkforceAssignment) error
}

type IdentityWorkforceTerminationRepository interface {
	TerminateIdentityWorkforce(context.Context, identitymodel.IdentityWorkforceTerminationMutation) (identitymodel.IdentityWorkforceTerminationResult, error)
}

type IdentityWorkforceLifecycleRepository interface {
	ApplyIdentityWorkforceLifecycle(context.Context, identitymodel.IdentityWorkforceLifecycleMutation) (identitymodel.IdentityWorkforceLifecycleResult, error)
}

type IdentityWorkforceOnboardingRepository interface {
	ApplyIdentityWorkforceOnboarding(context.Context, identitymodel.IdentityWorkforceOnboardingMutation) (identitymodel.IdentityWorkforceOnboardingResult, error)
}

type IdentityWorkforceTransferBatchRepository interface {
	GetIdentityWorkforceTransferBatchReceipt(context.Context, string, string) (identitymodel.IdentityWorkforceTransferBatchReceipt, bool, error)
	ApplyIdentityWorkforceTransferBatch(context.Context, identitymodel.IdentityWorkforceTransferBatchMutation) (identitymodel.IdentityWorkforceTransferBatchReceipt, error)
}

type IdentityUserLookupRepository interface {
	GetIdentityUser(context.Context, string, string) (identitymodel.IdentityUser, bool, error)
}

type IdentityUserDirectoryFactsRepository interface {
	ListIdentityUserDirectoryFacts(context.Context, string, []string) (identitymodel.IdentityUserDirectoryFacts, error)
}

type IdentityAccountDisableRepository interface {
	DisableIdentityAccount(context.Context, string, string) (int, error)
}

type IdentityRoleRequestDecisionRepository interface {
	ApplyIdentityRoleRequestDecision(context.Context, string, identitymodel.IdentityRoleRequest, []identitymodel.IdentityUserRoleAssignment, string) error
}

type IdentityUserRoleReconcileRepository interface {
	UpsertIdentityUserWithRoleAssignmentsAtomically(context.Context, string, identitymodel.IdentityUser, []identitymodel.IdentityUserRoleAssignment) error
}

type IdentityEntitlementBatchRepository interface {
	GetIdentityEntitlementBatchReceipt(context.Context, string, string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error)
	ApplyIdentityEntitlementBatch(context.Context, identitymodel.IdentityEntitlementBatchMutation) (identitymodel.IdentityEntitlementBatchReceipt, error)
}

type IdentityAccessReviewRepository interface {
	CreateIdentityAccessReview(context.Context, identitymodel.IdentityAccessReview) error
	ListIdentityAccessReviews(context.Context, string, string) ([]identitymodel.IdentityAccessReview, error)
	GetIdentityAccessReviewItem(context.Context, string, string) (identitymodel.IdentityAccessReviewItem, bool, error)
	GetIdentityAccessReviewDecisionReceipt(context.Context, string, string, string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error)
	ApplyIdentityAccessReviewDecision(context.Context, identitymodel.IdentityAccessReviewDecisionMutation) (identitymodel.IdentityAccessReviewDecisionReceipt, error)
}

// IdentityUserLocaleRepository is the narrow compare-and-swap persistence
// capability consumed only by current-user locale self-service.
type IdentityUserLocaleRepository interface {
	UpdateIdentityUserLocale(context.Context, string, string, string, int64) (identitymodel.IdentityUser, bool, error)
}

type IdentityRoleAuthorizationCommit struct {
	Role             identitymodel.IdentityRole
	PermissionKeys   *[]string
	DataScopes       *[]identitymodel.IdentityDataScopePolicy
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
	ApplyIdentityBootstrapAtomically(context.Context, string, []identitymodel.IdentityDepartment, []identitymodel.IdentityUser, []identitymodel.IdentityWorkforceProfile, []identitymodel.IdentityWorkforceAssignment, []identitymodel.IdentityUserRoleAssignment) error
	UpsertIdentityUser(context.Context, string, identitymodel.IdentityUser) error
	AssignIdentityUserRole(context.Context, string, identitymodel.IdentityUserRoleAssignment) error
	ListIdentityMenus(context.Context, string) ([]identitymodel.IdentityMenu, error)
	UpsertIdentityMenu(context.Context, string, identitymodel.IdentityMenu) error
	RemoveIdentityMenu(context.Context, string, string) error
	SetIdentityRoleMenus(context.Context, string, string, []string) error
	ListIdentityRoleMenuAssignments(context.Context, string, string) ([]identitymodel.IdentityRoleMenuAssignment, error)
}
