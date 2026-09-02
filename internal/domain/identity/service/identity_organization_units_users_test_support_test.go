package service

import (
	"context"
	"errors"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

var errIdentityOrganizationUnitUserEdge = errors.New("identity organization unit/user edge")

type identityOrganizationUnitUserRepository struct {
	identityrepository.IdentityRepository
	organizationUnits       []identitymodel.IdentityOrganizationUnit
	users                   []identitymodel.IdentityUser
	organizationUnitLists   [][]identitymodel.IdentityOrganizationUnit
	userLists               [][]identitymodel.IdentityUser
	listOrganizationUnitErr error
	listUserErr             error
	upsertOrganizationErr   error
	upsertOrganizationAt    int
	upsertOrganizationN     int
	upsertUserErr           error
	removeErr               error
	statusErr               error
	statusUser              string
	statusValue             identitymodel.IdentityStatus
	profileBindings         []identitymodel.IdentityProfileBinding
	profileBindingErr       error
	roleAssignments         []identitymodel.IdentityUserRoleAssignment
	roleAssignmentErr       error
	listOrganizationUnitAt  int
	listOrganizationUnitN   int
	listUserAt              int
	listUserN               int
	upsertUserN             int
}

func (r *identityOrganizationUnitUserRepository) ListIdentityUserRoleAssignments(context.Context, string, string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	if r.roleAssignmentErr != nil {
		return nil, r.roleAssignmentErr
	}
	return append([]identitymodel.IdentityUserRoleAssignment(nil), r.roleAssignments...), nil
}

func (r *identityOrganizationUnitUserRepository) ListIdentityProfileBindingsByUser(context.Context, string, string) ([]identitymodel.IdentityProfileBinding, error) {
	return append([]identitymodel.IdentityProfileBinding(nil), r.profileBindings...), r.profileBindingErr
}

func (r *identityOrganizationUnitUserRepository) ListIdentityOrganizationUnits(context.Context, string) ([]identitymodel.IdentityOrganizationUnit, error) {
	r.listOrganizationUnitN++
	if r.listOrganizationUnitErr != nil && (r.listOrganizationUnitAt == 0 || r.listOrganizationUnitAt == r.listOrganizationUnitN) {
		return nil, r.listOrganizationUnitErr
	}
	if r.listOrganizationUnitN <= len(r.organizationUnitLists) {
		return append([]identitymodel.IdentityOrganizationUnit(nil), r.organizationUnitLists[r.listOrganizationUnitN-1]...), nil
	}
	return append([]identitymodel.IdentityOrganizationUnit(nil), r.organizationUnits...), nil
}

func (r *identityOrganizationUnitUserRepository) UpsertIdentityOrganizationUnit(_ context.Context, _ string, unit identitymodel.IdentityOrganizationUnit) error {
	r.upsertOrganizationN++
	if r.upsertOrganizationErr != nil && (r.upsertOrganizationAt == 0 || r.upsertOrganizationAt == r.upsertOrganizationN) {
		return r.upsertOrganizationErr
	}
	for index := range r.organizationUnits {
		if r.organizationUnits[index].ID == unit.ID {
			r.organizationUnits[index] = unit
			return nil
		}
	}
	r.organizationUnits = append(r.organizationUnits, unit)
	return nil
}

func (r *identityOrganizationUnitUserRepository) UpsertIdentityOrganizationUnitsAtomically(ctx context.Context, workspace string, units []identitymodel.IdentityOrganizationUnit) error {
	before := append([]identitymodel.IdentityOrganizationUnit(nil), r.organizationUnits...)
	for _, unit := range units {
		if err := r.UpsertIdentityOrganizationUnit(ctx, workspace, unit); err != nil {
			r.organizationUnits = before
			return err
		}
	}
	return nil
}

func (r *identityOrganizationUnitUserRepository) ListIdentityUsers(context.Context, string) ([]identitymodel.IdentityUser, error) {
	r.listUserN++
	if r.listUserErr != nil && (r.listUserAt == 0 || r.listUserAt == r.listUserN) {
		return nil, r.listUserErr
	}
	if r.listUserN <= len(r.userLists) {
		return append([]identitymodel.IdentityUser(nil), r.userLists[r.listUserN-1]...), nil
	}
	return append([]identitymodel.IdentityUser(nil), r.users...), nil
}

func (r *identityOrganizationUnitUserRepository) GetIdentityUser(_ context.Context, _, id string) (identitymodel.IdentityUser, bool, error) {
	if r.listUserErr != nil {
		return identitymodel.IdentityUser{}, false, r.listUserErr
	}
	for _, user := range r.users {
		if user.ID == id {
			return user, true, nil
		}
	}
	return identitymodel.IdentityUser{}, false, nil
}

func (r *identityOrganizationUnitUserRepository) UpsertIdentityUser(_ context.Context, _ string, user identitymodel.IdentityUser) error {
	r.upsertUserN++
	if r.upsertUserErr != nil {
		return r.upsertUserErr
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

func (r *identityOrganizationUnitUserRepository) UpsertIdentityUsersAtomically(ctx context.Context, workspace string, users []identitymodel.IdentityUser) error {
	for _, user := range users {
		if err := r.UpsertIdentityUser(ctx, workspace, user); err != nil {
			return err
		}
	}
	return nil
}

func (r *identityOrganizationUnitUserRepository) RemoveIdentityUser(context.Context, string, string) error {
	return r.removeErr
}

func (r *identityOrganizationUnitUserRepository) SetIdentityUserStatus(_ context.Context, _, userID string, status identitymodel.IdentityStatus) error {
	r.statusUser, r.statusValue = userID, status
	return r.statusErr
}
