package identity

import (
	"context"
	"database/sql"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	organizationunitpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/directory/organizationunit"
	userpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/directory/user"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-orm/query"
)

func (s *SQLIdentityStore) organizationUnitStore() *organizationunitpersistence.Store {
	return organizationunitpersistence.New(s, nowString)
}

func (s *SQLIdentityStore) userStore() *userpersistence.Store {
	return userpersistence.New(s, nowString)
}

func (s *SQLIdentityStore) ListIdentityOrganizationUnits(ctx context.Context, workspaceID string) ([]identitymodel.IdentityOrganizationUnit, error) {
	return s.loadOrganizationUnits(ctx, workspaceID)
}

func (s *SQLIdentityStore) UpsertIdentityOrganizationUnit(ctx context.Context, workspaceID string, organizationUnit identitymodel.IdentityOrganizationUnit) error {
	return s.writeIdentityOrganizationUnit(ctx, s.db, workspaceID, organizationUnit)
}

func (s *SQLIdentityStore) UpsertIdentityOrganizationUnitsAtomically(ctx context.Context, workspaceID string, organizationUnits []identitymodel.IdentityOrganizationUnit) error {
	if _, err := identityWorkspaceID(workspaceID); err != nil {
		return err
	}
	if executor := transaction.ExecutorFromContext(ctx); executor != nil {
		for _, organizationUnit := range organizationUnits {
			if err := s.writeIdentityOrganizationUnit(ctx, executor, workspaceID, organizationUnit); err != nil {
				return err
			}
		}
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, organizationUnit := range organizationUnits {
		if err := s.writeIdentityOrganizationUnit(ctx, tx, workspaceID, organizationUnit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLIdentityStore) writeIdentityOrganizationUnit(ctx context.Context, execer identityUserExecer, workspaceID string, organizationUnit identitymodel.IdentityOrganizationUnit) error {
	return s.organizationUnitStore().Upsert(ctx, execer, workspaceID, organizationUnit)
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

func (s *SQLIdentityStore) loadOrganizationUnits(ctx context.Context, workspaceID string) ([]identitymodel.IdentityOrganizationUnit, error) {
	return s.organizationUnitStore().List(ctx, workspaceID)
}

func (s *SQLIdentityStore) loadUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	return s.userStore().List(ctx, workspaceID)
}
