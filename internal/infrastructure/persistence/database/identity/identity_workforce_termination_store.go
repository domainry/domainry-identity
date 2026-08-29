package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *SQLIdentityStore) TerminateIdentityWorkforce(ctx context.Context, mutation identitymodel.IdentityWorkforceTerminationMutation) (identitymodel.IdentityWorkforceTerminationResult, error) {
	return s.workforceLifecycleStore().Terminate(ctx, mutation)
}

func valueOrFallback(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
