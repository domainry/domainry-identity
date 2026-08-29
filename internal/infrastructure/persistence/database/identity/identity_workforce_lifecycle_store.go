package identity

import (
	"context"
	"database/sql"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	lifecyclepersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/workforce/lifecycle"
)

func (s *SQLIdentityStore) workforceLifecycleStore() lifecyclepersistence.Store {
	return lifecyclepersistence.New(s, nowString, s.writeIdentityUserTx, s.writeIdentityWorkforceProfileTx, s.writeIdentityWorkforceAssignmentTx, s.writeIdentityUserRoleAssignmentTx)
}

func (s *SQLIdentityStore) writeIdentityUserTx(ctx context.Context, tx *sql.Tx, workspaceID string, user identitymodel.IdentityUser) error {
	return s.writeIdentityUser(ctx, tx, workspaceID, user)
}

func (s *SQLIdentityStore) writeIdentityWorkforceProfileTx(ctx context.Context, tx *sql.Tx, workspaceID string, profile identitymodel.IdentityWorkforceProfile) error {
	return s.writeIdentityWorkforceProfile(ctx, tx, workspaceID, profile)
}

func (s *SQLIdentityStore) writeIdentityWorkforceAssignmentTx(ctx context.Context, tx *sql.Tx, workspaceID string, assignment identitymodel.IdentityWorkforceAssignment) error {
	return s.writeIdentityWorkforceAssignment(ctx, tx, workspaceID, assignment)
}

func (s *SQLIdentityStore) writeIdentityUserRoleAssignmentTx(ctx context.Context, tx *sql.Tx, workspaceID string, assignment identitymodel.IdentityUserRoleAssignment) error {
	return s.writeIdentityUserRoleAssignment(ctx, tx, workspaceID, assignment)
}

func (s *SQLIdentityStore) ApplyIdentityWorkforceLifecycle(ctx context.Context, mutation identitymodel.IdentityWorkforceLifecycleMutation) (identitymodel.IdentityWorkforceLifecycleResult, error) {
	return s.workforceLifecycleStore().Apply(ctx, mutation)
}

func (s *SQLIdentityStore) applyIdentityWorkforceLifecycleTx(ctx context.Context, tx *sql.Tx, workspaceID string, mutation identitymodel.IdentityWorkforceLifecycleMutation) (identitymodel.IdentityWorkforceLifecycleResult, error) {
	return s.workforceLifecycleStore().ApplyTx(ctx, tx, workspaceID, mutation)
}
