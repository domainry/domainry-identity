package identity

import (
	"context"
	"database/sql"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	departmentpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/directory/department"
	userpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/directory/user"
	"github.com/domainry/domainry-orm/query"
)

func (s *SQLIdentityStore) departmentStore() *departmentpersistence.Store {
	return departmentpersistence.New(s, nowString)
}

func (s *SQLIdentityStore) userStore() *userpersistence.Store {
	return userpersistence.New(s, nowString)
}

func (s *SQLIdentityStore) ListIdentityDepartments(ctx context.Context, workspaceID string) ([]identitymodel.IdentityDepartment, error) {
	return s.loadDepartments(ctx, workspaceID)
}

func (s *SQLIdentityStore) UpsertIdentityDepartment(ctx context.Context, workspaceID string, department identitymodel.IdentityDepartment) error {
	return s.writeIdentityDepartment(ctx, s.db, workspaceID, department)
}

func (s *SQLIdentityStore) writeIdentityDepartment(ctx context.Context, execer identityUserExecer, workspaceID string, department identitymodel.IdentityDepartment) error {
	return s.departmentStore().Upsert(ctx, execer, workspaceID, department)
}

func (s *SQLIdentityStore) ListIdentityUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	return s.loadUsers(ctx, workspaceID)
}

func (s *SQLIdentityStore) ListIdentityProfileBindingsByUser(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityProfileBinding, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	return NewIdentityProfileBindingStore(s).ListIdentityProfileBindingsByUser(ctx, workspaceID, userID)
}

func (s *SQLIdentityStore) GetIdentityUser(ctx context.Context, workspaceID, userID string) (identitymodel.IdentityUser, bool, error) {
	return s.userStore().Get(ctx, workspaceID, userID)
}

func (s *SQLIdentityStore) UpsertIdentityUser(ctx context.Context, workspaceID string, user identitymodel.IdentityUser) error {
	return s.writeIdentityUser(ctx, s.db, workspaceID, user)
}

func (s *SQLIdentityStore) UpdateIdentityUserLocale(ctx context.Context, workspaceID, userID, locale string, expectedVersion int64) (identitymodel.IdentityUser, bool, error) {
	return s.userStore().UpdateLocale(ctx, workspaceID, userID, locale, expectedVersion)
}

func (s *SQLIdentityStore) UpsertIdentityUsersAtomically(ctx context.Context, workspaceID string, users []identitymodel.IdentityUser) error {
	return s.userStore().UpsertMany(ctx, workspaceID, users)
}

type identityUserExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SQLIdentityStore) writeIdentityUser(ctx context.Context, execer identityUserExecer, workspaceID string, user identitymodel.IdentityUser) error {
	return s.userStore().Upsert(ctx, execer, workspaceID, user)
}

func (s *SQLIdentityStore) UpsertIdentityUserWithRoleAssignmentsAtomically(
	ctx context.Context,
	workspaceID string,
	user identitymodel.IdentityUser,
	assignments []identitymodel.IdentityUserRoleAssignment,
) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.writeIdentityUser(ctx, tx, workspaceID, user); err != nil {
		return err
	}
	statement, arguments, err := query.NewWorkspaceDeleteBuilder(s.sqlRenderer(), "_identity_user_role_assignments", workspaceID).Where(query.Equal("user_id", user.ID)).Build()
	if err != nil {
		return fmt.Errorf("build identity user role reset: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return err
	}
	for _, assignment := range assignments {
		if err := s.writeIdentityUserRoleAssignment(ctx, tx, workspaceID, assignment); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLIdentityStore) RemoveIdentityUser(ctx context.Context, workspaceID, userID string) error {
	return s.userStore().Remove(ctx, workspaceID, userID)
}

func (s *SQLIdentityStore) SetIdentityUserStatus(ctx context.Context, workspaceID, userID string, status identitymodel.IdentityStatus) error {
	return s.userStore().SetStatus(ctx, workspaceID, userID, status)
}

func (s *SQLIdentityStore) loadDepartments(ctx context.Context, workspaceID string) ([]identitymodel.IdentityDepartment, error) {
	return s.departmentStore().List(ctx, workspaceID)
}

func (s *SQLIdentityStore) loadUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	return s.userStore().List(ctx, workspaceID)
}
