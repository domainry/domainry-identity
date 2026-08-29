package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	workforcepersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/workforce/core"
)

func (s *SQLIdentityStore) workforceStore() *workforcepersistence.Store {
	return workforcepersistence.New(s, nowString)
}

func (s *SQLIdentityStore) ListIdentityWorkforceProfiles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityWorkforceProfile, error) {
	return s.workforceStore().ListProfiles(ctx, workspaceID)
}

func (s *SQLIdentityStore) GetIdentityWorkforceProfile(ctx context.Context, workspaceID, profileID string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	return s.workforceStore().GetProfile(ctx, workspaceID, profileID)
}

func (s *SQLIdentityStore) UpsertIdentityWorkforceProfile(ctx context.Context, workspaceID string, profile identitymodel.IdentityWorkforceProfile) error {
	return s.workforceStore().UpsertProfileAtomically(ctx, workspaceID, profile)
}

func (s *SQLIdentityStore) writeIdentityWorkforceProfile(ctx context.Context, execer identityUserExecer, workspaceID string, profile identitymodel.IdentityWorkforceProfile) error {
	return s.workforceStore().UpsertProfile(ctx, execer, workspaceID, profile)
}

func (s *SQLIdentityStore) ListIdentityWorkforceAssignments(ctx context.Context, workspaceID, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	return s.workforceStore().ListAssignments(ctx, workspaceID, profileID)
}

func (s *SQLIdentityStore) GetIdentityWorkforceAssignment(ctx context.Context, workspaceID, assignmentID string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	return s.workforceStore().GetAssignment(ctx, workspaceID, assignmentID)
}

func (s *SQLIdentityStore) UpsertIdentityWorkforceAssignment(ctx context.Context, workspaceID string, assignment identitymodel.IdentityWorkforceAssignment) error {
	return s.workforceStore().UpsertAssignmentAtomically(ctx, workspaceID, assignment)
}

func (s *SQLIdentityStore) writeIdentityWorkforceAssignment(ctx context.Context, execer identityUserExecer, workspaceID string, assignment identitymodel.IdentityWorkforceAssignment) error {
	return s.workforceStore().UpsertAssignment(ctx, execer, workspaceID, assignment)
}
