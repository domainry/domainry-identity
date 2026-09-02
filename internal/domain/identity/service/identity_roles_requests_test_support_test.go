package service

import (
	"context"
	"errors"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type identityRolesRepositoryStub struct {
	identityrepository.IdentityRepository
	roles                []identitymodel.IdentityRole
	users                []identitymodel.IdentityUser
	assignments          []identitymodel.IdentityUserRoleAssignment
	requests             []identitymodel.IdentityRoleRequest
	err                  error
	listRolesErr         error
	listRolesCalls       int
	listRolesFunc        func(int) ([]identitymodel.IdentityRole, error)
	listUsersErr         error
	getUserErr           error
	listAssignmentsErr   error
	listRequestsErr      error
	updateRequestErr     error
	assignErr            error
	removeErr            error
	profileBindingsErr   error
	assigned             []identitymodel.IdentityUserRoleAssignment
	removedRole          string
	removedUser          string
	removedUserRole      string
	statusRole           string
	status               identitymodel.IdentityStatus
	upsertedRole         identitymodel.IdentityRole
	updatedRequest       identitymodel.IdentityRoleRequest
	reconciledUser       identitymodel.IdentityUser
	reconciledRoles      []identitymodel.IdentityUserRoleAssignment
	reconcileErr         error
	profileBindings      []identitymodel.IdentityProfileBinding
	organizationUnits    []identitymodel.IdentityOrganizationUnit
	organizationUnitsErr error
}

func (r *identityRolesRepositoryStub) UpsertIdentityUserWithRoleAssignmentsAtomically(_ context.Context, _ string, user identitymodel.IdentityUser, assignments []identitymodel.IdentityUserRoleAssignment) error {
	if r.reconcileErr != nil {
		return r.reconcileErr
	}
	r.reconciledUser = user
	r.reconciledRoles = append([]identitymodel.IdentityUserRoleAssignment(nil), assignments...)
	return nil
}

func (r *identityRolesRepositoryStub) ListIdentityProfileBindingsByUser(_ context.Context, _, userID string) ([]identitymodel.IdentityProfileBinding, error) {
	if r.profileBindingsErr != nil {
		return nil, r.profileBindingsErr
	}
	out := []identitymodel.IdentityProfileBinding{}
	for _, binding := range r.profileBindings {
		if binding.IdentityUserID == userID {
			out = append(out, binding)
		}
	}
	return out, r.err
}

func (r *identityRolesRepositoryStub) ListIdentityOrganizationUnits(context.Context, string) ([]identitymodel.IdentityOrganizationUnit, error) {
	if r.organizationUnitsErr != nil {
		return nil, r.organizationUnitsErr
	}
	if r.organizationUnits != nil {
		return append([]identitymodel.IdentityOrganizationUnit(nil), r.organizationUnits...), nil
	}
	return []identitymodel.IdentityOrganizationUnit{{ID: "organizationUnit", Name: "OrganizationUnit", Status: identitymodel.IdentityStatusActive}}, nil
}

func (r *identityRolesRepositoryStub) ListIdentityRoles(context.Context, string) ([]identitymodel.IdentityRole, error) {
	r.listRolesCalls++
	if r.listRolesFunc != nil {
		return r.listRolesFunc(r.listRolesCalls)
	}
	if r.listRolesErr != nil {
		return nil, r.listRolesErr
	}
	if r.err != nil {
		return nil, r.err
	}
	return append([]identitymodel.IdentityRole(nil), r.roles...), nil
}
func (r *identityRolesRepositoryStub) ListIdentityUsers(context.Context, string) ([]identitymodel.IdentityUser, error) {
	if r.listUsersErr != nil {
		return nil, r.listUsersErr
	}
	if r.err != nil {
		return nil, r.err
	}
	return append([]identitymodel.IdentityUser(nil), r.users...), nil
}
func (r *identityRolesRepositoryStub) GetIdentityUser(_ context.Context, _, id string) (identitymodel.IdentityUser, bool, error) {
	if r.getUserErr != nil {
		return identitymodel.IdentityUser{}, false, r.getUserErr
	}
	if r.err != nil {
		return identitymodel.IdentityUser{}, false, r.err
	}
	for _, user := range r.users {
		if user.ID == id {
			return user, true, nil
		}
	}
	return identitymodel.IdentityUser{}, false, nil
}
func (r *identityRolesRepositoryStub) UpsertIdentityRole(_ context.Context, _ string, role identitymodel.IdentityRole) error {
	if r.err != nil {
		return r.err
	}
	r.upsertedRole = role
	return nil
}
func (r *identityRolesRepositoryStub) RemoveIdentityRole(_ context.Context, _, id string) error {
	if r.err != nil {
		return r.err
	}
	r.removedRole = id
	return nil
}
func (r *identityRolesRepositoryStub) SetIdentityRoleStatus(_ context.Context, _, id string, status identitymodel.IdentityStatus) error {
	if r.err != nil {
		return r.err
	}
	r.statusRole, r.status = id, status
	return nil
}
func (r *identityRolesRepositoryStub) AssignIdentityUserRole(_ context.Context, _ string, assignment identitymodel.IdentityUserRoleAssignment) error {
	if r.assignErr != nil {
		return r.assignErr
	}
	if r.err != nil {
		return r.err
	}
	r.assigned = append(r.assigned, assignment)
	return nil
}
func (r *identityRolesRepositoryStub) RemoveIdentityUserRole(_ context.Context, _, userID, roleID string) error {
	if r.removeErr != nil {
		return r.removeErr
	}
	if r.err != nil {
		return r.err
	}
	r.removedUser, r.removedUserRole = userID, roleID
	return nil
}
func (r *identityRolesRepositoryStub) ListIdentityUserRoleAssignments(context.Context, string, string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	if r.listAssignmentsErr != nil {
		return nil, r.listAssignmentsErr
	}
	if r.err != nil {
		return nil, r.err
	}
	return append([]identitymodel.IdentityUserRoleAssignment(nil), r.assignments...), nil
}
func (r *identityRolesRepositoryStub) CreateIdentityRoleRequest(_ context.Context, _ string, request identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error) {
	if r.err != nil {
		return identitymodel.IdentityRoleRequest{}, r.err
	}
	request.ID = "request-created"
	r.requests = append(r.requests, request)
	return request, nil
}
func (r *identityRolesRepositoryStub) ListIdentityRoleRequests(_ context.Context, _, status, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	if r.listRequestsErr != nil {
		return nil, r.listRequestsErr
	}
	if r.err != nil {
		return nil, r.err
	}
	out := []identitymodel.IdentityRoleRequest{}
	for _, request := range r.requests {
		if status != "" && request.Status != status {
			continue
		}
		if userID != "" && request.UserID != userID {
			continue
		}
		out = append(out, request)
	}
	return out, nil
}
func (r *identityRolesRepositoryStub) UpdateIdentityRoleRequest(_ context.Context, _ string, request identitymodel.IdentityRoleRequest) error {
	if r.updateRequestErr != nil {
		return r.updateRequestErr
	}
	if r.err != nil {
		return r.err
	}
	r.updatedRequest = request
	return nil
}
func (r *identityRolesRepositoryStub) ApplyIdentityRoleRequestDecision(_ context.Context, _ string, request identitymodel.IdentityRoleRequest, assignments []identitymodel.IdentityUserRoleAssignment, _ string) error {
	if r.assignErr != nil {
		return r.assignErr
	}
	if r.updateRequestErr != nil {
		return r.updateRequestErr
	}
	if r.err != nil {
		return r.err
	}
	r.assigned = append(r.assigned, assignments...)
	r.updatedRequest = request
	return nil
}

func identityRolesFixture() (*identityRolesRepositoryStub, *IdentityDomainService) {
	repository := &identityRolesRepositoryStub{
		roles: []identitymodel.IdentityRole{
			{ID: "member-id", Key: "member", Label: "Member", Status: identitymodel.IdentityStatusActive},
			{ID: "viewer-id", Key: "viewer", Label: "Viewer", Status: identitymodel.IdentityStatusActive},
			{ID: "admin-id", Key: "admin", Label: "Admin", Status: identitymodel.IdentityStatusActive},
			{ID: "owner-id", Key: "owner", Label: "Owner", Status: identitymodel.IdentityStatusActive},
			{ID: "workspace-admin-id", Key: "team_workspace_admin", Label: "Workspace Admin", Status: identitymodel.IdentityStatusActive},
			{ID: "permission-admin-id", Key: "security", Label: "Security", Status: identitymodel.IdentityStatusActive},
			{ID: "disabled-id", Key: "disabled", Label: "Disabled", Status: identitymodel.IdentityStatusDisabled},
		},
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}, {ID: "disabled-user", Status: identitymodel.IdentityStatusDisabled}},
	}
	service, err := NewIdentityDomainService(repository, nil).ForWorkspace("workspace-1")
	if err != nil {
		panic(err)
	}
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "member", Name: "Member", RecordScope: "all_records"},
		{Key: "viewer", Name: "Viewer", RecordScope: "all_records"},
		{Key: "admin", Name: "Admin", Permissions: []string{"identity.roles.list"}, RecordScope: "all_records", RiskLevel: identitymodel.IdentityRoleRiskPrivileged},
		{Key: "owner", Name: "Owner", Permissions: []string{"identity.roles.list"}, RecordScope: "all_records", RiskLevel: identitymodel.IdentityRoleRiskPrivileged},
		{Key: "team_workspace_admin", Name: "Workspace Admin", Permissions: []string{"identity.roles.list"}, RecordScope: "all_records", RiskLevel: identitymodel.IdentityRoleRiskPrivileged},
		{Key: "security", Name: "Security", Permissions: []string{"identity.roles.list"}, RecordScope: "all_records", RiskLevel: identitymodel.IdentityRoleRiskPrivileged},
	})
	return repository, service
}

var errIdentityRolesRepository = errors.New("identity roles repository failed")
