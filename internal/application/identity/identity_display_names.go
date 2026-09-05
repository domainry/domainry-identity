package identity

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *IdentityApplicationService) ResolveProjectionDisplayNames(ctx context.Context, userIDs, organizationUnitIDs []string) ([]identitymodel.IdentityUser, []identitymodel.IdentityOrganizationUnit, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	return scoped.ResolveProjectionDisplayNames(ctx, userIDs, organizationUnitIDs)
}
