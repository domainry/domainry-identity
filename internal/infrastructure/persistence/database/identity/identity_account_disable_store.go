package identity

import (
	"context"

	accountpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/account"
)

func (s *SQLIdentityStore) DisableIdentityAccount(ctx context.Context, workspaceID, userID string) (int, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return 0, err
	}
	return accountpersistence.New(s, nowString).Disable(ctx, workspaceID, userID)
}
