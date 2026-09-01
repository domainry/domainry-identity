package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/domainry/domainry-foundation/apperror"
	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type identityHTTPUserSecurity struct {
	revoked         int
	revokedFactorID string
	issuedUserID    string
	initialPassword string
	profile         authdomain.UserSecurityProfile
	err             error
}

type identityHTTPDeletionInspector struct {
	inspection identityapplication.IdentityUserDeletionInspection
	err        error
}

func (i *identityHTTPDeletionInspector) InspectIdentityUserDeletion(context.Context, string, string) (identityapplication.IdentityUserDeletionInspection, error) {
	return i.inspection, i.err
}

func (s *identityHTTPUserSecurity) UserSecurityProfile(context.Context, string, string) (authdomain.UserSecurityProfile, error) {
	return s.profile, s.err
}

func (s *identityHTTPUserSecurity) IssueInitialPassword(_ context.Context, _, userID string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	s.issuedUserID = userID
	if s.initialPassword == "" {
		s.initialPassword = "Vd!9random-initial-password"
	}
	return s.initialPassword, nil
}

func (s *identityHTTPUserSecurity) UnlockUser(context.Context, string, string) error {
	return s.err
}

func (s *identityHTTPUserSecurity) ForceLogoutUser(context.Context, string, string) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	s.revoked++
	return 1, nil
}

func (s *identityHTTPUserSecurity) ForceLogoutUserIdempotent(_ context.Context, _ identitymodel.Principal, _ string, _ string) (authdomain.RevokeOtherSessionsResult, bool, error) {
	count, err := s.ForceLogoutUser(context.Background(), "", "")
	return authdomain.RevokeOtherSessionsResult{RevokedSessions: count}, false, err
}

func (s *identityHTTPUserSecurity) RevokeMFAFactor(_ context.Context, _, _, factorID string) error {
	s.revokedFactorID = factorID
	return s.err
}

type identityHTTPRepository struct {
	identityrepository.IdentityRepository
	err                               error
	upsertUserErr                     error
	listUsersErrAfterUpsert           error
	dropUpsertUser                    bool
	upsertUserCalls                   int
	listDepartmentsErr                error
	upsertDepartmentErr               error
	upsertDepartmentCalls             int
	storeDepartmentOnUpsert           bool
	removeUserErr                     error
	removeUserCalls                   int
	upsertRoleErr                     error
	removeRoleErr                     error
	statusErr                         error
	assignErr                         error
	removeAssignmentErr               error
	updateRequestErr                  error
	upsertMenuErr                     error
	listMenusErr                      error
	removeMenusErr                    error
	setRoleMenusErr                   error
	listMenuLinksErr                  error
	commitAuthorizationErr            error
	listPermissionsErr                error
	listDataScopesErr                 error
	listFieldPermissionsErr           error
	listWorkforceAssignmentsErr       error
	failListWorkforceAssignmentsAfter int
	listWorkforceAssignmentsCalls     int
	failListRolesAfter                int
	listRolesCalls                    int
	failListMenusAfterUpsert          bool
	failListLinksAfterSet             bool
	failListPermissionsAfterSet       bool
	failListDataScopesAfterSet        bool
	failListFieldPermissionsAfterSet  bool
	users                             []identitymodel.IdentityUser
	departments                       []identitymodel.IdentityDepartment
	roles                             []identitymodel.IdentityRole
	menus                             []identitymodel.IdentityMenu
	assignments                       []identitymodel.IdentityUserRoleAssignment
	entitlementReceipts               map[string]identitymodel.IdentityEntitlementBatchReceipt
	workforceTransferReceipts         map[string]identitymodel.IdentityWorkforceTransferBatchReceipt
	menuLinks                         []identitymodel.IdentityRoleMenuAssignment
	permissionAssignments             []identitymodel.IdentityRolePermissionAssignment
	dataScopes                        []identitymodel.IdentityDataScopePolicy
	fieldPermissions                  []identitymodel.IdentityFieldPermission
	requests                          []identitymodel.IdentityRoleRequest
	workforceProfiles                 []identitymodel.IdentityWorkforceProfile
	workforceAssignments              []identitymodel.IdentityWorkforceAssignment
	profileBindings                   []identitymodel.IdentityProfileBinding
	lastRole                          identitymodel.IdentityRole
	lastUser                          identitymodel.IdentityUser
	lastDepartment                    identitymodel.IdentityDepartment
	lastMenu                          identitymodel.IdentityMenu
	lastStatus                        identitymodel.IdentityStatus
	lastUserID                        string
	lastRoleID                        string
	lastMenuIDs                       []string
	lastWorkforceProfile              identitymodel.IdentityWorkforceProfile
	lastWorkforceAssignment           identitymodel.IdentityWorkforceAssignment
	lastWorkforceTermination          identitymodel.IdentityWorkforceTerminationMutation
	lastWorkforceLifecycle            identitymodel.IdentityWorkforceLifecycleMutation
	lastWorkforceOnboarding           identitymodel.IdentityWorkforceOnboardingMutation
}

func (r *identityHTTPRepository) ListIdentityDepartments(context.Context, string) ([]identitymodel.IdentityDepartment, error) {
	return append([]identitymodel.IdentityDepartment(nil), r.departments...), firstIdentityHTTPError(r.listDepartmentsErr, r.err)
}

func (r *identityHTTPRepository) UpsertIdentityDepartment(_ context.Context, _ string, department identitymodel.IdentityDepartment) error {
	r.upsertDepartmentCalls++
	r.lastDepartment = department
	for index := range r.departments {
		if r.departments[index].ID == department.ID {
			r.departments[index] = department
			return firstIdentityHTTPError(r.upsertDepartmentErr, r.err)
		}
	}
	if r.storeDepartmentOnUpsert {
		r.departments = append(r.departments, department)
	}
	return firstIdentityHTTPError(r.upsertDepartmentErr, r.err)
}

func (r *identityHTTPRepository) ListIdentityUsers(context.Context, string) ([]identitymodel.IdentityUser, error) {
	if r.upsertUserCalls > 0 && r.listUsersErrAfterUpsert != nil {
		return nil, r.listUsersErrAfterUpsert
	}
	return append([]identitymodel.IdentityUser(nil), r.users...), r.err
}
func (r *identityHTTPRepository) ListIdentityProfileBindingsByUser(_ context.Context, _, userID string) ([]identitymodel.IdentityProfileBinding, error) {
	out := []identitymodel.IdentityProfileBinding{}
	for _, binding := range r.profileBindings {
		if binding.IdentityUserID == userID {
			out = append(out, binding)
		}
	}
	return out, r.err
}
func (r *identityHTTPRepository) GetIdentityUser(_ context.Context, _, userID string) (identitymodel.IdentityUser, bool, error) {
	for _, user := range r.users {
		if user.ID == userID {
			return user, true, r.err
		}
	}
	return identitymodel.IdentityUser{}, false, r.err
}
func (r *identityHTTPRepository) UpsertIdentityUser(_ context.Context, _ string, user identitymodel.IdentityUser) error {
	r.lastUser = user
	if err := firstIdentityHTTPError(r.upsertUserErr, r.err); err != nil {
		return err
	}
	r.upsertUserCalls++
	if r.dropUpsertUser {
		return nil
	}
	for index := range r.users {
		if r.users[index].ID == user.ID {
			r.users[index] = user
			return nil
		}
	}
	r.users = append(r.users, user)
	return nil
}
func (r *identityHTTPRepository) UpsertIdentityUsersAtomically(_ context.Context, _ string, users []identitymodel.IdentityUser) error {
	if len(users) > 0 {
		r.lastUser = users[len(users)-1]
	}
	return firstIdentityHTTPError(r.upsertUserErr, r.err)
}
func (r *identityHTTPRepository) UpsertIdentityUserWithRoleAssignmentsAtomically(_ context.Context, _ string, user identitymodel.IdentityUser, assignments []identitymodel.IdentityUserRoleAssignment) error {
	r.lastUser = user
	r.lastUserID = user.ID
	r.assignments = append([]identitymodel.IdentityUserRoleAssignment(nil), assignments...)
	return firstIdentityHTTPError(r.assignErr, r.err)
}
func (r *identityHTTPRepository) RemoveIdentityUser(_ context.Context, _, userID string) error {
	r.removeUserCalls++
	r.lastUserID = userID
	return firstIdentityHTTPError(r.removeUserErr, r.err)
}
func (r *identityHTTPRepository) SetIdentityUserStatus(_ context.Context, _ string, userID string, status identitymodel.IdentityStatus) error {
	r.lastUserID, r.lastStatus = userID, status
	return firstIdentityHTTPError(r.statusErr, r.err)
}

func (r *identityHTTPRepository) TerminateIdentityWorkforce(_ context.Context, mutation identitymodel.IdentityWorkforceTerminationMutation) (identitymodel.IdentityWorkforceTerminationResult, error) {
	if r.err != nil {
		return identitymodel.IdentityWorkforceTerminationResult{}, r.err
	}
	r.lastWorkforceTermination = mutation
	r.lastWorkforceProfile = mutation.Profile
	for index := range r.workforceProfiles {
		if r.workforceProfiles[index].ID == mutation.Profile.ID {
			r.workforceProfiles[index] = mutation.Profile
		}
	}
	var ended, revoked int64
	for index := range r.workforceAssignments {
		if r.workforceAssignments[index].WorkforceProfileID == mutation.Profile.ID && r.workforceAssignments[index].Status == identitymodel.IdentityStatusActive {
			r.workforceAssignments[index].Status = identitymodel.IdentityStatusDisabled
			r.workforceAssignments[index].EffectiveTo = mutation.EffectiveAt
			ended++
		}
	}
	for index := range r.assignments {
		if r.assignments[index].WorkforceProfileID == mutation.Profile.ID && r.assignments[index].Status == "active" {
			r.assignments[index].Status = "revoked"
			revoked++
		}
	}
	var preserved int64
	for _, binding := range r.profileBindings {
		if binding.IdentityUserID == mutation.Profile.IdentityUserID {
			preserved++
		}
	}
	return identitymodel.IdentityWorkforceTerminationResult{
		Profile: mutation.Profile, EndedAssignmentCount: ended, RevokedEntitlementCount: revoked,
		PreservedProfileBindings: preserved,
	}, nil
}

func (r *identityHTTPRepository) ApplyIdentityWorkforceLifecycle(_ context.Context, mutation identitymodel.IdentityWorkforceLifecycleMutation) (identitymodel.IdentityWorkforceLifecycleResult, error) {
	if r.err != nil {
		return identitymodel.IdentityWorkforceLifecycleResult{}, r.err
	}
	r.lastWorkforceLifecycle = mutation
	if mutation.Profile != nil {
		r.lastWorkforceProfile = *mutation.Profile
	}
	if len(mutation.UpsertAssignments) > 0 {
		r.lastWorkforceAssignment = mutation.UpsertAssignments[len(mutation.UpsertAssignments)-1]
	}
	return identitymodel.IdentityWorkforceLifecycleResult{
		Profile: mutation.Profile, Assignments: mutation.UpsertAssignments,
		EndedAssignmentCount: int64(len(mutation.EndAssignments)),
	}, nil
}

func (r *identityHTTPRepository) ApplyIdentityWorkforceOnboarding(_ context.Context, mutation identitymodel.IdentityWorkforceOnboardingMutation) (identitymodel.IdentityWorkforceOnboardingResult, error) {
	if r.err != nil {
		return identitymodel.IdentityWorkforceOnboardingResult{}, r.err
	}
	r.lastWorkforceOnboarding = mutation
	return identitymodel.IdentityWorkforceOnboardingResult{
		User: mutation.User, Profile: mutation.Profile, Assignment: mutation.Assignment,
		RoleAssignments: mutation.RoleAssignments,
	}, nil
}

func (r *identityHTTPRepository) ListIdentityWorkforceProfiles(context.Context, string) ([]identitymodel.IdentityWorkforceProfile, error) {
	return append([]identitymodel.IdentityWorkforceProfile(nil), r.workforceProfiles...), r.err
}
func (r *identityHTTPRepository) GetIdentityWorkforceProfile(_ context.Context, _, profileID string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	for _, profile := range r.workforceProfiles {
		if profile.ID == profileID {
			return profile, true, r.err
		}
	}
	return identitymodel.IdentityWorkforceProfile{}, false, r.err
}
func (r *identityHTTPRepository) UpsertIdentityWorkforceProfile(_ context.Context, _ string, profile identitymodel.IdentityWorkforceProfile) error {
	r.lastWorkforceProfile = profile
	if r.err != nil {
		return r.err
	}
	for index := range r.workforceProfiles {
		if r.workforceProfiles[index].ID == profile.ID {
			r.workforceProfiles[index] = profile
			return nil
		}
	}
	r.workforceProfiles = append(r.workforceProfiles, profile)
	return nil
}
func (r *identityHTTPRepository) ListIdentityWorkforceAssignments(_ context.Context, _, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	r.listWorkforceAssignmentsCalls++
	if r.failListWorkforceAssignmentsAfter > 0 && r.listWorkforceAssignmentsCalls > r.failListWorkforceAssignmentsAfter {
		return nil, errIdentityHTTPTest
	}
	out := []identitymodel.IdentityWorkforceAssignment{}
	for _, assignment := range r.workforceAssignments {
		if profileID == "" || assignment.WorkforceProfileID == profileID {
			out = append(out, assignment)
		}
	}
	return out, firstIdentityHTTPError(r.listWorkforceAssignmentsErr, r.err)
}
func (r *identityHTTPRepository) GetIdentityWorkforceAssignment(_ context.Context, _, assignmentID string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	for _, assignment := range r.workforceAssignments {
		if assignment.ID == assignmentID {
			return assignment, true, r.err
		}
	}
	return identitymodel.IdentityWorkforceAssignment{}, false, r.err
}
func (r *identityHTTPRepository) UpsertIdentityWorkforceAssignment(_ context.Context, _ string, assignment identitymodel.IdentityWorkforceAssignment) error {
	r.lastWorkforceAssignment = assignment
	if r.err != nil {
		return r.err
	}
	for index := range r.workforceAssignments {
		if r.workforceAssignments[index].ID == assignment.ID {
			r.workforceAssignments[index] = assignment
			return nil
		}
	}
	r.workforceAssignments = append(r.workforceAssignments, assignment)
	return nil
}

func (r *identityHTTPRepository) ListIdentityRoles(context.Context, string) ([]identitymodel.IdentityRole, error) {
	r.listRolesCalls++
	if r.failListRolesAfter > 0 && r.listRolesCalls > r.failListRolesAfter {
		return nil, errIdentityHTTPTest
	}
	return append([]identitymodel.IdentityRole(nil), r.roles...), r.err
}
func (r *identityHTTPRepository) UpsertIdentityRole(_ context.Context, _ string, role identitymodel.IdentityRole) error {
	r.lastRole = role
	return firstIdentityHTTPError(r.upsertRoleErr, r.err)
}
func (r *identityHTTPRepository) RemoveIdentityRole(_ context.Context, _ string, roleID string) error {
	r.lastRoleID = roleID
	return firstIdentityHTTPError(r.removeRoleErr, r.err)
}
func (r *identityHTTPRepository) SetIdentityRoleStatus(_ context.Context, _ string, roleID string, status identitymodel.IdentityStatus) error {
	r.lastRoleID, r.lastStatus = roleID, status
	return firstIdentityHTTPError(r.statusErr, r.err)
}
func (r *identityHTTPRepository) ListIdentityUserRoleAssignments(_ context.Context, _, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	r.lastUserID = userID
	return append([]identitymodel.IdentityUserRoleAssignment(nil), r.assignments...), r.err
}
func (r *identityHTTPRepository) AssignIdentityUserRole(_ context.Context, _ string, assignment identitymodel.IdentityUserRoleAssignment) error {
	r.lastUserID, r.lastRoleID = assignment.UserID, assignment.RoleID
	if err := firstIdentityHTTPError(r.assignErr, r.err); err != nil {
		return err
	}
	r.assignments = append(r.assignments, assignment)
	return nil
}
func (r *identityHTTPRepository) RemoveIdentityUserRole(_ context.Context, _, userID, roleID string) error {
	r.lastUserID, r.lastRoleID = userID, roleID
	return firstIdentityHTTPError(r.removeAssignmentErr, r.err)
}
func (r *identityHTTPRepository) GetIdentityEntitlementBatchReceipt(_ context.Context, _, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	receipt, found := r.entitlementReceipts[idempotencyKey]
	return receipt, found, r.err
}
func (r *identityHTTPRepository) ApplyIdentityEntitlementBatch(_ context.Context, mutation identitymodel.IdentityEntitlementBatchMutation) (identitymodel.IdentityEntitlementBatchReceipt, error) {
	if err := firstIdentityHTTPError(r.assignErr, r.err); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	if r.entitlementReceipts == nil {
		r.entitlementReceipts = map[string]identitymodel.IdentityEntitlementBatchReceipt{}
	}
	r.assignments = append(r.assignments, mutation.Assignments...)
	receipt := identitymodel.IdentityEntitlementBatchReceipt{
		ID: "receipt-" + mutation.IdempotencyKey, WorkspaceID: mutation.WorkspaceID, ActorID: mutation.ActorID,
		IdempotencyKey: mutation.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint, Items: mutation.Items, CreatedAt: "now",
	}
	r.entitlementReceipts[mutation.IdempotencyKey] = receipt
	return receipt, nil
}
func (r *identityHTTPRepository) GetIdentityWorkforceTransferBatchReceipt(_ context.Context, _, idempotencyKey string) (identitymodel.IdentityWorkforceTransferBatchReceipt, bool, error) {
	receipt, found := r.workforceTransferReceipts[idempotencyKey]
	return receipt, found, r.err
}
func (r *identityHTTPRepository) ApplyIdentityWorkforceTransferBatch(_ context.Context, mutation identitymodel.IdentityWorkforceTransferBatchMutation) (identitymodel.IdentityWorkforceTransferBatchReceipt, error) {
	if r.err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, r.err
	}
	if r.workforceTransferReceipts == nil {
		r.workforceTransferReceipts = map[string]identitymodel.IdentityWorkforceTransferBatchReceipt{}
	}
	receipt := identitymodel.IdentityWorkforceTransferBatchReceipt{
		ID: "receipt-" + mutation.IdempotencyKey, WorkspaceID: mutation.WorkspaceID, ActorID: mutation.ActorID,
		IdempotencyKey: mutation.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint, Items: mutation.Items, CreatedAt: "now",
	}
	r.workforceTransferReceipts[mutation.IdempotencyKey] = receipt
	return receipt, nil
}
func (r *identityHTTPRepository) ListIdentityRoleRequests(_ context.Context, _, status, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	r.lastStatus, r.lastUserID = identitymodel.IdentityStatus(status), userID
	return append([]identitymodel.IdentityRoleRequest(nil), r.requests...), r.err
}
func (r *identityHTTPRepository) UpdateIdentityRoleRequest(_ context.Context, _ string, request identitymodel.IdentityRoleRequest) error {
	for index := range r.requests {
		if r.requests[index].ID == request.ID {
			r.requests[index] = request
		}
	}
	return firstIdentityHTTPError(r.updateRequestErr, r.err)
}
func (r *identityHTTPRepository) ApplyIdentityRoleRequestDecision(_ context.Context, _ string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, _ string) error {
	if r.assignErr != nil {
		return r.assignErr
	}
	if r.updateRequestErr != nil {
		return r.updateRequestErr
	}
	for _, assignment := range assignments {
		r.lastUserID, r.lastRoleID = assignment.UserID, assignment.RoleID
		r.assignments = append(r.assignments, assignment)
	}
	for index := range r.requests {
		if r.requests[index].ID == request.ID {
			r.requests[index] = request
		}
	}
	return r.err
}
func (r *identityHTTPRepository) ListIdentityMenus(context.Context, string) ([]identitymodel.IdentityMenu, error) {
	return append([]identitymodel.IdentityMenu(nil), r.menus...), firstIdentityHTTPError(r.listMenusErr, r.err)
}
func (r *identityHTTPRepository) UpsertIdentityMenu(_ context.Context, _ string, menu identitymodel.IdentityMenu) error {
	r.lastMenu = menu
	if err := firstIdentityHTTPError(r.upsertMenuErr, r.err); err != nil {
		return err
	}
	for index := range r.menus {
		if r.menus[index].ID == menu.ID {
			r.menus[index] = menu
			if r.failListMenusAfterUpsert {
				r.listMenusErr = errIdentityHTTPTest
			}
			return nil
		}
	}
	r.menus = append(r.menus, menu)
	if r.failListMenusAfterUpsert {
		r.listMenusErr = errIdentityHTTPTest
	}
	return nil
}
func (r *identityHTTPRepository) RemoveIdentityMenu(context.Context, string, string) error {
	return firstIdentityHTTPError(r.removeMenusErr, r.err)
}
func (r *identityHTTPRepository) RemoveIdentityMenusAtomically(_ context.Context, _ string, menus []identitymodel.IdentityMenu) error {
	for _, menu := range menus {
		r.lastMenuIDs = append(r.lastMenuIDs, menu.ID)
	}
	return r.err
}
func (r *identityHTTPRepository) SetIdentityRoleMenus(_ context.Context, _, roleID string, menuIDs []string) error {
	r.lastRoleID = roleID
	r.lastMenuIDs = append([]string(nil), menuIDs...)
	if err := firstIdentityHTTPError(r.setRoleMenusErr, r.err); err != nil {
		return err
	}
	r.menuLinks = make([]identitymodel.IdentityRoleMenuAssignment, 0, len(menuIDs))
	for _, menuID := range menuIDs {
		r.menuLinks = append(r.menuLinks, identitymodel.IdentityRoleMenuAssignment{RoleID: roleID, MenuID: menuID})
	}
	if r.failListLinksAfterSet {
		r.listMenuLinksErr = errIdentityHTTPTest
	}
	return nil
}
func (r *identityHTTPRepository) ListIdentityRoleMenuAssignments(_ context.Context, _, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	r.lastRoleID = roleID
	return append([]identitymodel.IdentityRoleMenuAssignment(nil), r.menuLinks...), firstIdentityHTTPError(r.listMenuLinksErr, r.err)
}
func (r *identityHTTPRepository) SetIdentityRolePermissions(context.Context, string, string, []string) error {
	return nil
}
func (r *identityHTTPRepository) ListIdentityRolePermissionAssignments(_ context.Context, _, roleID string) ([]identitymodel.IdentityRolePermissionAssignment, error) {
	r.lastRoleID = roleID
	return append([]identitymodel.IdentityRolePermissionAssignment(nil), r.permissionAssignments...), firstIdentityHTTPError(r.listPermissionsErr, r.err)
}
func (r *identityHTTPRepository) SetIdentityRoleDataScopes(context.Context, string, string, []identitymodel.IdentityDataScopePolicy) error {
	return nil
}
func (r *identityHTTPRepository) ListIdentityRoleDataScopes(_ context.Context, _, roleID string) ([]identitymodel.IdentityDataScopePolicy, error) {
	r.lastRoleID = roleID
	return append([]identitymodel.IdentityDataScopePolicy(nil), r.dataScopes...), firstIdentityHTTPError(r.listDataScopesErr, r.err)
}
func (r *identityHTTPRepository) SetIdentityRoleFieldPermissions(context.Context, string, string, []identitymodel.IdentityFieldPermission) error {
	return nil
}
func (r *identityHTTPRepository) ListIdentityRoleFieldPermissions(_ context.Context, _, roleID string) ([]identitymodel.IdentityFieldPermission, error) {
	r.lastRoleID = roleID
	return append([]identitymodel.IdentityFieldPermission(nil), r.fieldPermissions...), firstIdentityHTTPError(r.listFieldPermissionsErr, r.err)
}

func firstIdentityHTTPError(errors ...error) error {
	for _, err := range errors {
		if err != nil {
			return err
		}
	}
	return nil
}

type identityHTTPResponse struct {
	status int
	value  any
	err    error
}

type identityHTTPPermissionRepository struct {
	records []identitymodel.IdentityPermissionDefinitionRecord
}

func (r *identityHTTPPermissionRepository) ListIdentityPermissionDefinitions(context.Context, string) ([]identitymodel.IdentityPermissionDefinitionRecord, error) {
	return append([]identitymodel.IdentityPermissionDefinitionRecord(nil), r.records...), nil
}

func (r *identityHTTPPermissionRepository) GetIdentityPermissionDefinition(_ context.Context, _ string, key string) (identitymodel.IdentityPermissionDefinitionRecord, bool, error) {
	for _, record := range r.records {
		if record.PermissionKey == key {
			return record, true, nil
		}
	}
	return identitymodel.IdentityPermissionDefinitionRecord{}, false, nil
}

func (r *identityHTTPPermissionRepository) SetIdentityPermissionDefinitionEnabled(_ context.Context, _ string, key string, enabled bool) (bool, error) {
	for index := range r.records {
		if r.records[index].PermissionKey == key && r.records[index].DefinitionStatus == identitymodel.IdentityPermissionDefinitionActive && r.records[index].Enabled != enabled {
			r.records[index].Enabled = enabled
			return true, nil
		}
	}
	return false, nil
}

func (r *identityHTTPPermissionRepository) ReconcileIdentityPermissionDefinitions(_ context.Context, request identitymodel.IdentityPermissionReconcileRequest) (identitymodel.IdentityPermissionReconcileReceipt, error) {
	r.records = append([]identitymodel.IdentityPermissionDefinitionRecord(nil), request.Definitions...)
	return identitymodel.IdentityPermissionReconcileReceipt{WorkspaceID: request.WorkspaceID, SourceOwner: request.SourceOwner, SnapshotHash: request.SnapshotHash}, nil
}

func newIdentityHTTPPermissionCatalog() (*identityapplication.IdentityPermissionCatalogApplicationService, []string) {
	registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		panic(err)
	}
	records := registry.OwnedPermissionDefinitions(identityapplication.IdentityBuiltinAuthorizationOwner)
	keys := make([]string, 0, len(records))
	for index := range records {
		records[index].WorkspaceID = "workspace-1"
		records[index].DefinitionStatus = identitymodel.IdentityPermissionDefinitionActive
		records[index].Enabled = true
		keys = append(keys, records[index].PermissionKey)
	}
	repository := &identityHTTPPermissionRepository{records: records}
	catalog, err := identityapplication.NewIdentityPermissionCatalogApplicationService(repository, registry, "workspace-1")
	if err != nil {
		panic(err)
	}
	if err := catalog.ReloadCurrentSnapshot(context.Background()); err != nil {
		panic(err)
	}
	return catalog, keys
}

func newIdentityHTTPHandler(repo *identityHTTPRepository, inspectors ...identityapplication.IdentityUserDeletionInspector) (*IdentityHandler, *identityHTTPResponse) {
	permissions := []identitymodel.IdentityPermissionDefinition{{
		Key: "identity.users.list", Label: "List users",
		DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true,
	}}
	var inspector identityapplication.IdentityUserDeletionInspector = &identityHTTPDeletionInspector{}
	if len(inspectors) > 0 {
		inspector = inspectors[0]
	}
	service := identityapplication.NewIdentityApplicationServiceWithDependencies(repo, permissions, identityapplication.IdentityApplicationServiceDependencies{UserDeletionInspector: inspector})
	roleDefinitions := make([]identitymodel.RoleSchema, 0, len(repo.roles))
	for _, role := range repo.roles {
		roleDefinitions = append(roleDefinitions, identitymodel.RoleSchema{Key: role.Key, Permissions: []string{"identity.users.list"}})
	}
	service.ReplaceRoleDefinitions(roleDefinitions)
	permissionMap := service.PermissionDefinitions()
	response := &identityHTTPResponse{}
	permissionCatalog, permissionKeys := newIdentityHTTPPermissionCatalog()
	principal := identitymodel.Principal{Known: true, UserID: "reviewer-1", WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Permissions: permissionKeys, RecordScope: "all_records"}}
	return NewIdentityHandler(IdentityDependencies{
		Users: service, Roles: service, Policies: service, Menus: service, Authorization: service,
		UserSecurity: &identityHTTPUserSecurity{},
		Governance: identityapplication.NewIdentityGovernanceApplicationService(repo, permissionMap, func() map[string]definitionmodel.ObjectSchema {
			return map[string]definitionmodel.ObjectSchema{"customer": {Key: "customer", Fields: []definitionmodel.FieldSchema{{Key: "name", Type: "text"}}}}
		}),
		Principal: func(*http.Request) identitymodel.Principal { return principal },
		WriteJSON: func(_ http.ResponseWriter, status int, value any) { response.status, response.value = status, value },
		WriteError: func(_ http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) {
			response.status = status
		},
		WriteServiceError: func(_ http.ResponseWriter, _ *http.Request, err error) {
			response.status, response.err = http.StatusInternalServerError, err
			switch apperror.CodeOf(err) {
			case "backend.identity.user_already_exists":
				response.status = http.StatusConflict
			case "backend.identity.user_deletion_blocked":
				response.status = http.StatusConflict
			case "backend.identity.user_security_unavailable", "backend.identity.user_deletion_inspector_unavailable":
				response.status = http.StatusServiceUnavailable
			}
		},
		DecodeJSON: func(_ http.ResponseWriter, request *http.Request, value any) bool {
			if err := json.NewDecoder(request.Body).Decode(value); err != nil {
				response.status, response.err = http.StatusBadRequest, err
				return false
			}
			return true
		},
		SecurityAudit: func(*http.Request, string, string, map[string]any) {},
		SecurityPrincipal: func(*http.Request, identitymodel.Principal, string, string, map[string]any) {
		},
		Authoring:         identityauthoring.NewService(identityauthoring.NewMemoryRepository(), nil, nil),
		PermissionCatalog: permissionCatalog,
	}), response
}

var errIdentityHTTPTest = errors.New("identity repository unavailable")
