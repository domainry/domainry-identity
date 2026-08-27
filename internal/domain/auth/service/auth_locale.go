package service

import (
	"context"
	"errors"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// UpdateUserLocale delegates the narrow self-profile mutation to Identity.
// Authorization and target selection remain at the authenticated application
// boundary; this method accepts no generic user patch.
func (s *AuthDomainService) UpdateUserLocale(ctx context.Context, workspaceID, userID, locale string, expectedVersion int64) (identitymodel.IdentityUser, error) {
	if s.localeIdentity == nil {
		return identitymodel.IdentityUser{}, internalError("update current user locale", errors.New("identity locale service is unavailable"))
	}
	return s.localeIdentity.UpdateUserLocale(ctx, workspaceID, userID, locale, expectedVersion)
}
