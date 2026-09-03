package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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

func (s *identityHTTPUserSecurity) UserSecurityProfileGoverned(ctx context.Context, principal identitymodel.Principal, userID string) (authdomain.UserSecurityProfile, error) {
	return s.UserSecurityProfile(ctx, principal.WorkspaceID, userID)
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

func (s *identityHTTPUserSecurity) UnlockUserGoverned(ctx context.Context, principal identitymodel.Principal, userID string) error {
	return s.UnlockUser(ctx, principal.WorkspaceID, userID)
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

func (s *identityHTTPUserSecurity) RevokeMFAFactorGoverned(ctx context.Context, principal identitymodel.Principal, userID, factorID string) error {
	return s.RevokeMFAFactor(ctx, principal.WorkspaceID, userID, factorID)
}

type identityHTTPRepository struct {
	identityrepository.IdentityRepository
	err                              error
	upsertUserErr                    error
	listUsersErrAfterUpsert          error
	dropUpsertUser                   bool
	upsertUserCalls                  int
	listOrganizationUnitsErr         error
	upsertOrganizationUnitErr        error
	upsertOrganizationUnitCalls      int
	storeOrganizationUnitOnUpsert    bool
	removeUserErr                    error
	removeUserCalls                  int
	upsertRoleErr                    error
	removeRoleErr                    error
	statusErr                        error
	assignErr                        error
	removeAssignmentErr              error
	updateRequestErr                 error
	upsertMenuErr                    error
	listMenusErr                     error
	removeMenusErr                   error
	setRoleMenusErr                  error
	listMenuLinksErr                 error
	commitAuthorizationErr           error
	listPermissionsErr               error
	listFieldPermissionsErr          error
	failListRolesAfter               int
	listRolesCalls                   int
	failListMenusAfterUpsert         bool
	failListLinksAfterSet            bool
	failListPermissionsAfterSet      bool
	failListFieldPermissionsAfterSet bool
	users                            []identitymodel.IdentityUser
	organizationUnits                []identitymodel.IdentityOrganizationUnit
	roles                            []identitymodel.IdentityRole
	menus                            []identitymodel.IdentityMenu
	assignments                      []identitymodel.IdentityUserRoleAssignment
	entitlementReceipts              map[string]identitymodel.IdentityEntitlementBatchReceipt
	menuLinks                        []identitymodel.IdentityRoleMenuAssignment
	permissionAssignments            []identitymodel.IdentityRolePermissionAssignment
	fieldPermissions                 []identitymodel.IdentityFieldPermission
	requests                         []identitymodel.IdentityRoleRequest
	profileBindings                  []identitymodel.IdentityProfileBinding
	lastRole                         identitymodel.IdentityRole
	lastUser                         identitymodel.IdentityUser
	lastOrganizationUnit             identitymodel.IdentityOrganizationUnit
	lastMenu                         identitymodel.IdentityMenu
	lastStatus                       identitymodel.IdentityStatus
	lastUserID                       string
	lastRoleID                       string
	lastMenuIDs                      []string
}

func (r *identityHTTPRepository) ListIdentityOrganizationUnits(context.Context, string) ([]identitymodel.IdentityOrganizationUnit, error) {
	return append([]identitymodel.IdentityOrganizationUnit(nil), r.organizationUnits...), firstIdentityHTTPError(r.listOrganizationUnitsErr, r.err)
}

func (r *identityHTTPRepository) ListIdentityOrganizationUnitsWithinDataScope(_ context.Context, _ string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityOrganizationUnit, error) {
	if err := firstIdentityHTTPError(r.listOrganizationUnitsErr, r.err); err != nil {
		return nil, err
	}
	if scope.Unrestricted {
		return append([]identitymodel.IdentityOrganizationUnit(nil), r.organizationUnits...), nil
	}
	allowed := map[string]bool{}
	for _, id := range scope.Normalized().OwnerOrgIDs {
		allowed[id] = true
	}
	items := make([]identitymodel.IdentityOrganizationUnit, 0, len(r.organizationUnits))
	for _, item := range r.organizationUnits {
		if allowed[item.ID] {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *identityHTTPRepository) GetIdentityOrganizationUnitWithinDataScope(ctx context.Context, workspaceID, organizationUnitID string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityOrganizationUnit, bool, error) {
	items, err := r.ListIdentityOrganizationUnitsWithinDataScope(ctx, workspaceID, scope)
	if err != nil {
		return identitymodel.IdentityOrganizationUnit{}, false, err
	}
	for _, item := range items {
		if item.ID == organizationUnitID {
			return item, true, nil
		}
	}
	return identitymodel.IdentityOrganizationUnit{}, false, nil
}

func (r *identityHTTPRepository) UpsertIdentityOrganizationUnit(_ context.Context, _ string, organizationUnit identitymodel.IdentityOrganizationUnit) error {
	r.upsertOrganizationUnitCalls++
	r.lastOrganizationUnit = organizationUnit
	for index := range r.organizationUnits {
		if r.organizationUnits[index].ID == organizationUnit.ID {
			r.organizationUnits[index] = organizationUnit
			return firstIdentityHTTPError(r.upsertOrganizationUnitErr, r.err)
		}
	}
	if r.storeOrganizationUnitOnUpsert {
		r.organizationUnits = append(r.organizationUnits, organizationUnit)
	}
	return firstIdentityHTTPError(r.upsertOrganizationUnitErr, r.err)
}

func (r *identityHTTPRepository) UpsertIdentityOrganizationUnitsAtomically(ctx context.Context, workspace string, organizationUnits []identitymodel.IdentityOrganizationUnit) error {
	before := append([]identitymodel.IdentityOrganizationUnit(nil), r.organizationUnits...)
	for _, organizationUnit := range organizationUnits {
		if err := r.UpsertIdentityOrganizationUnit(ctx, workspace, organizationUnit); err != nil {
			r.organizationUnits = before
			return err
		}
	}
	return nil
}

func (r *identityHTTPRepository) UpsertIdentityOrganizationUnitsWithinDataScopeAtomically(ctx context.Context, workspace string, organizationUnits []identitymodel.IdentityOrganizationUnit, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	if !scope.Unrestricted {
		allowed := map[string]bool{}
		for _, id := range scope.Normalized().OwnerOrgIDs {
			allowed[id] = true
		}
		existing := map[string]bool{}
		existingParent := map[string]string{}
		for _, item := range r.organizationUnits {
			existing[item.ID] = true
			if item.ParentID != nil {
				existingParent[item.ID] = strings.TrimSpace(*item.ParentID)
			}
		}
		for _, item := range organizationUnits {
			parentID := ""
			if item.ParentID != nil {
				parentID = strings.TrimSpace(*item.ParentID)
			}
			parentChanged := !existing[item.ID] || existingParent[item.ID] != parentID
			if existing[item.ID] && !allowed[item.ID] || parentChanged && (parentID == "" || !allowed[parentID]) {
				return false, nil
			}
		}
	}
	return true, r.UpsertIdentityOrganizationUnitsAtomically(ctx, workspace, organizationUnits)
}

func (r *identityHTTPRepository) ListIdentityUsers(context.Context, string) ([]identitymodel.IdentityUser, error) {
	if r.upsertUserCalls > 0 && r.listUsersErrAfterUpsert != nil {
		return nil, r.listUsersErrAfterUpsert
	}
	return append([]identitymodel.IdentityUser(nil), r.users...), r.err
}
func (r *identityHTTPRepository) ListIdentityUsersWithinDataScope(_ context.Context, _ string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUser, error) {
	if r.upsertUserCalls > 0 && r.listUsersErrAfterUpsert != nil {
		return nil, r.listUsersErrAfterUpsert
	}
	out := make([]identitymodel.IdentityUser, 0, len(r.users))
	for _, user := range r.users {
		if identityHTTPUserMatchesDataScope(user, scope) {
			out = append(out, user)
		}
	}
	return out, r.err
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
func (r *identityHTTPRepository) GetIdentityUserWithinDataScope(_ context.Context, _ string, userID string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityUser, bool, error) {
	if r.upsertUserCalls > 0 && r.listUsersErrAfterUpsert != nil {
		return identitymodel.IdentityUser{}, false, r.listUsersErrAfterUpsert
	}
	for _, user := range r.users {
		if user.ID == userID && identityHTTPUserMatchesDataScope(user, scope) {
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
func (r *identityHTTPRepository) CreateIdentityUser(ctx context.Context, workspaceID string, user identitymodel.IdentityUser) error {
	for _, existing := range r.users {
		if existing.ID == user.ID {
			return errors.New("identity user already exists")
		}
	}
	return r.UpsertIdentityUser(ctx, workspaceID, user)
}
func (r *identityHTTPRepository) UpsertIdentityUsersAtomically(_ context.Context, _ string, users []identitymodel.IdentityUser) error {
	if len(users) == 0 {
		return firstIdentityHTTPError(r.upsertUserErr, r.err)
	}
	r.lastUser = users[0]
	if err := firstIdentityHTTPError(r.upsertUserErr, r.err); err != nil {
		return err
	}
	r.upsertUserCalls++
	if r.dropUpsertUser {
		return nil
	}
	for _, user := range users {
		updated := false
		for index := range r.users {
			if r.users[index].ID == user.ID {
				r.users[index] = user
				updated = true
				break
			}
		}
		if !updated {
			r.users = append(r.users, user)
		}
	}
	return nil
}
func (r *identityHTTPRepository) UpdateIdentityUsersWithinDataScopeAtomically(_ context.Context, _ string, users []identitymodel.IdentityUser, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	if len(users) == 0 {
		return false, firstIdentityHTTPError(r.upsertUserErr, r.err)
	}
	r.lastUser = users[0]
	if err := firstIdentityHTTPError(r.upsertUserErr, r.err); err != nil {
		return false, err
	}
	for _, update := range users {
		matched := false
		for _, existing := range r.users {
			if existing.ID == update.ID && identityHTTPUserMatchesDataScope(existing, scope) {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	r.upsertUserCalls++
	if r.dropUpsertUser {
		for _, update := range users {
			for index := range r.users {
				if r.users[index].ID == update.ID {
					r.users = append(r.users[:index], r.users[index+1:]...)
					break
				}
			}
		}
		return true, nil
	}
	for _, update := range users {
		for index := range r.users {
			if r.users[index].ID == update.ID {
				r.users[index] = update
			}
		}
	}
	return true, nil
}
func (r *identityHTTPRepository) UpsertIdentityUserWithRoleAssignmentsAtomically(_ context.Context, _ string, user identitymodel.IdentityUser, assignments []identitymodel.IdentityUserRoleAssignment) error {
	r.lastUser = user
	r.lastUserID = user.ID
	r.assignments = append([]identitymodel.IdentityUserRoleAssignment(nil), assignments...)
	return firstIdentityHTTPError(r.assignErr, r.err)
}
func (r *identityHTTPRepository) UpsertIdentityUserWithRoleAssignmentsWithinDataScopeAtomically(_ context.Context, _ string, user identitymodel.IdentityUser, assignments []identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	r.lastUser, r.lastUserID = user, user.ID
	if err := firstIdentityHTTPError(r.assignErr, r.err); err != nil {
		return false, err
	}
	for _, existing := range r.users {
		if existing.ID == user.ID && identityHTTPUserMatchesDataScope(existing, scope) {
			r.assignments = append([]identitymodel.IdentityUserRoleAssignment(nil), assignments...)
			return true, nil
		}
	}
	return false, nil
}
func (r *identityHTTPRepository) RemoveIdentityUser(_ context.Context, _, userID string) error {
	r.removeUserCalls++
	r.lastUserID = userID
	return firstIdentityHTTPError(r.removeUserErr, r.err)
}
func (r *identityHTTPRepository) RemoveIdentityUserWithinDataScope(_ context.Context, _ string, userID string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	r.removeUserCalls++
	r.lastUserID = userID
	if err := firstIdentityHTTPError(r.removeUserErr, r.err); err != nil {
		return false, err
	}
	for index, user := range r.users {
		if user.ID == userID && identityHTTPUserMatchesDataScope(user, scope) {
			r.users = append(r.users[:index], r.users[index+1:]...)
			return true, nil
		}
	}
	return false, nil
}
func (r *identityHTTPRepository) SetIdentityUserStatus(_ context.Context, _ string, userID string, status identitymodel.IdentityStatus) error {
	r.lastUserID, r.lastStatus = userID, status
	return firstIdentityHTTPError(r.statusErr, r.err)
}
func (r *identityHTTPRepository) SetIdentityUserStatusWithinDataScope(_ context.Context, _ string, userID string, status identitymodel.IdentityStatus, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	r.lastUserID, r.lastStatus = userID, status
	if err := firstIdentityHTTPError(r.statusErr, r.err); err != nil {
		return false, err
	}
	for index, user := range r.users {
		if user.ID == userID && identityHTTPUserMatchesDataScope(user, scope) {
			r.users[index].Status = status
			return true, nil
		}
	}
	return false, nil
}

func identityHTTPUserMatchesDataScope(user identitymodel.IdentityUser, scope identitymodel.IdentityDataScopeFilter) bool {
	scope = scope.Normalized()
	if scope.Unrestricted {
		return true
	}
	for _, userID := range scope.OwnerUserIDs {
		if user.ID == userID {
			return true
		}
	}
	for _, orgID := range scope.OwnerOrgIDs {
		if user.OrgID == orgID {
			return true
		}
	}
	return false
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
func (r *identityHTTPRepository) ListIdentityUserRoleAssignmentsWithinDataScope(_ context.Context, _ string, userID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUserRoleAssignment, error) {
	r.lastUserID = userID
	if r.err != nil {
		return nil, r.err
	}
	allowed := map[string]bool{}
	for _, user := range r.users {
		allowed[user.ID] = identityHTTPUserMatchesDataScope(user, scope)
	}
	out := []identitymodel.IdentityUserRoleAssignment{}
	for _, assignment := range r.assignments {
		if (userID == "" || assignment.UserID == userID) && allowed[assignment.UserID] {
			out = append(out, assignment)
		}
	}
	return out, nil
}
func (r *identityHTTPRepository) AssignIdentityUserRole(_ context.Context, _ string, assignment identitymodel.IdentityUserRoleAssignment) error {
	r.lastUserID, r.lastRoleID = assignment.UserID, assignment.RoleID
	if err := firstIdentityHTTPError(r.assignErr, r.err); err != nil {
		return err
	}
	r.assignments = append(r.assignments, assignment)
	return nil
}
func (r *identityHTTPRepository) AssignIdentityUserRoleWithinDataScope(_ context.Context, _ string, assignment identitymodel.IdentityUserRoleAssignment, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	r.lastUserID, r.lastRoleID = assignment.UserID, assignment.RoleID
	if err := firstIdentityHTTPError(r.assignErr, r.err); err != nil {
		return false, err
	}
	for _, user := range r.users {
		if user.ID == assignment.UserID && identityHTTPUserMatchesDataScope(user, scope) {
			r.assignments = append(r.assignments, assignment)
			return true, nil
		}
	}
	return false, nil
}
func (r *identityHTTPRepository) RemoveIdentityUserRole(_ context.Context, _, userID, roleID string) error {
	r.lastUserID, r.lastRoleID = userID, roleID
	return firstIdentityHTTPError(r.removeAssignmentErr, r.err)
}
func (r *identityHTTPRepository) RemoveIdentityUserRoleWithinDataScope(_ context.Context, _ string, userID, roleID string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	r.lastUserID, r.lastRoleID = userID, roleID
	if err := firstIdentityHTTPError(r.removeAssignmentErr, r.err); err != nil {
		return false, err
	}
	for _, user := range r.users {
		if user.ID == userID && identityHTTPUserMatchesDataScope(user, scope) {
			return true, nil
		}
	}
	return false, nil
}
func (r *identityHTTPRepository) GetIdentityEntitlementBatchReceipt(_ context.Context, _, idempotencyKey string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	receipt, found := r.entitlementReceipts[idempotencyKey]
	return receipt, found, r.err
}
func (r *identityHTTPRepository) GetIdentityEntitlementBatchReceiptWithinDataScope(ctx context.Context, workspaceID, idempotencyKey string, _ identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	return r.GetIdentityEntitlementBatchReceipt(ctx, workspaceID, idempotencyKey)
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
func (r *identityHTTPRepository) ApplyIdentityEntitlementBatchWithinDataScope(ctx context.Context, mutation identitymodel.IdentityEntitlementBatchMutation, _ identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	receipt, err := r.ApplyIdentityEntitlementBatch(ctx, mutation)
	return receipt, err == nil, err
}
func (r *identityHTTPRepository) ListIdentityRoleRequests(_ context.Context, _, status, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	r.lastStatus, r.lastUserID = identitymodel.IdentityStatus(status), userID
	return append([]identitymodel.IdentityRoleRequest(nil), r.requests...), r.err
}
func (r *identityHTTPRepository) ListIdentityRoleRequestsWithinDataScope(_ context.Context, _ string, status, userID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityRoleRequest, error) {
	r.lastStatus, r.lastUserID = identitymodel.IdentityStatus(status), userID
	if r.err != nil {
		return nil, r.err
	}
	allowed := map[string]bool{}
	for _, user := range r.users {
		allowed[user.ID] = identityHTTPUserMatchesDataScope(user, scope)
	}
	out := []identitymodel.IdentityRoleRequest{}
	for _, request := range r.requests {
		if (status == "" || request.Status == status) && (userID == "" || request.UserID == userID) && allowed[request.UserID] {
			out = append(out, request)
		}
	}
	return out, nil
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
func (r *identityHTTPRepository) ApplyIdentityRoleRequestDecisionWithinDataScope(ctx context.Context, workspaceID string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, expectedStatus string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	for _, user := range r.users {
		if user.ID == request.UserID && identityHTTPUserMatchesDataScope(user, scope) {
			if err := r.ApplyIdentityRoleRequestDecision(ctx, workspaceID, request, assignments, expectedStatus); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
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
		roleDefinitions = append(roleDefinitions, identitymodel.RoleSchema{Key: role.Key, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.users.list")})
	}
	service.ReplaceRoleDefinitions(roleDefinitions)
	permissionMap := service.PermissionDefinitions()
	response := &identityHTTPResponse{}
	permissionCatalog, permissionKeys := newIdentityHTTPPermissionCatalog()
	principal := identitymodel.Principal{Known: true, UserID: "reviewer-1", WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{
		Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, permissionKeys...),
	}}
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
