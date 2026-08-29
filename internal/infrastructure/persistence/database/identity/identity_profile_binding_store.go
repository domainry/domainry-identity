package identity

import (
	"context"
	"database/sql"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	profilebindingpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/profilebinding"
)

type IdentityProfileBindingStore struct {
	store lifecycleSQLStore
}

func NewIdentityProfileBindingStore(store lifecycleSQLStore) *IdentityProfileBindingStore {
	return &IdentityProfileBindingStore{store: store}
}

func (s *IdentityProfileBindingStore) owner() *profilebindingpersistence.Store {
	var store lifecycleSQLStore
	if s != nil {
		store = s.store
	}
	return profilebindingpersistence.New(store)
}

func (s *IdentityProfileBindingStore) GetIdentityProfileBinding(ctx context.Context, workspaceID, objectKey, profileID string) (identitymodel.IdentityProfileBinding, bool, error) {
	return s.owner().GetIdentityProfileBinding(ctx, workspaceID, objectKey, profileID)
}

func (s *IdentityProfileBindingStore) GetIdentityProfileBindingByKey(ctx context.Context, workspaceID, bindingKey, profileID string) (identitymodel.IdentityProfileBinding, bool, error) {
	return s.owner().GetIdentityProfileBindingByKey(ctx, workspaceID, bindingKey, profileID)
}

func (s *IdentityProfileBindingStore) ListIdentityProfileBindingsByUser(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityProfileBinding, error) {
	return s.owner().ListIdentityProfileBindingsByUser(ctx, workspaceID, userID)
}

func (s *IdentityProfileBindingStore) IdentityRoleBindingActive(ctx context.Context, workspaceID, bindingKey, profileID, userID string) (bool, error) {
	return s.owner().IdentityRoleBindingActive(ctx, workspaceID, bindingKey, profileID, userID)
}

func (s *IdentityProfileBindingStore) GetIdentityProfileBindingReceipt(ctx context.Context, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, bool, error) {
	return s.owner().GetIdentityProfileBindingReceipt(ctx, mutation)
}

func (s *IdentityProfileBindingStore) ExecuteIdentityProfileBindingMutation(ctx context.Context, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, error) {
	return s.owner().ExecuteIdentityProfileBindingMutation(ctx, mutation)
}

func (s *IdentityProfileBindingStore) ListIdentityProfileBindingEvents(ctx context.Context, workspaceID, objectKey, profileID string) ([]identitymodel.IdentityProfileBindingEvent, error) {
	return s.owner().ListIdentityProfileBindingEvents(ctx, workspaceID, objectKey, profileID)
}

func (s *IdentityProfileBindingStore) synchronizeSystemManagedRoles(ctx context.Context, tx *sql.Tx, mutation identitymodel.IdentityProfileBindingMutation, previousUserID, nextUserID, now string) error {
	return s.owner().SynchronizeSystemManagedRoles(ctx, tx, mutation, previousUserID, nextUserID, now)
}

func (s *IdentityProfileBindingStore) updateProfileIdentityUser(ctx context.Context, tx *sql.Tx, mutation identitymodel.IdentityProfileBindingMutation, currentUserID, desiredUserID, now string) error {
	return s.owner().UpdateProfileIdentityUser(ctx, tx, mutation, currentUserID, desiredUserID, now)
}

func scanIdentityProfileBinding(row interface{ Scan(...any) error }) (identitymodel.IdentityProfileBinding, error) {
	return profilebindingpersistence.Scan(row)
}

func identityProfileBindingTransition(mutation identitymodel.IdentityProfileBindingMutation, currentUserID string) (identitymodel.IdentityProfileBindingStatus, string, error) {
	return profilebindingpersistence.Transition(mutation, currentUserID)
}

func validateIdentityProfileBindingMutation(mutation identitymodel.IdentityProfileBindingMutation) error {
	return profilebindingpersistence.ValidateMutation(mutation)
}

func normalizeProfileBindingWriteError(err error) error {
	return profilebindingpersistence.NormalizeWriteError(err)
}
