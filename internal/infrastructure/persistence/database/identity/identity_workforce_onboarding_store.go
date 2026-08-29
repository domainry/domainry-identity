package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *SQLIdentityStore) ApplyIdentityWorkforceOnboarding(ctx context.Context, mutation identitymodel.IdentityWorkforceOnboardingMutation) (identitymodel.IdentityWorkforceOnboardingResult, error) {
	return s.workforceLifecycleStore().Onboard(ctx, mutation)
}
