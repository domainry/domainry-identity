package service

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

// ResolveProjectionDisplayNames loads only the requested Identity rows. The
// data-scope repositories compile these ID sets into storage predicates, so a
// record page never requires loading the whole user or organization directory.
func (s *IdentityDomainService) ResolveProjectionDisplayNames(ctx context.Context, userIDs, organizationUnitIDs []string) ([]identitymodel.IdentityUser, []identitymodel.IdentityOrganizationUnit, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	users := []identitymodel.IdentityUser{}
	if len(userIDs) > 0 {
		repository, ok := s.repo.(identityrepository.IdentityUserDataScopeRepository)
		if !ok {
			return nil, nil, internalError("identity user display-name projection repository unavailable", nil)
		}
		var err error
		users, err = repository.ListIdentityUsersWithinDataScope(ctx, s.workspace, identitymodel.IdentityDataScopeFilter{OwnerUserIDs: userIDs})
		if err != nil {
			return nil, nil, err
		}
	}
	organizationUnits := []identitymodel.IdentityOrganizationUnit{}
	if len(organizationUnitIDs) > 0 {
		repository, ok := s.repo.(identityrepository.IdentityOrganizationUnitDataScopeRepository)
		if !ok {
			return nil, nil, internalError("identity organization display-name projection repository unavailable", nil)
		}
		var err error
		organizationUnits, err = repository.ListIdentityOrganizationUnitsWithinDataScope(ctx, s.workspace, identitymodel.IdentityDataScopeFilter{OwnerOrgIDs: organizationUnitIDs})
		if err != nil {
			return nil, nil, err
		}
	}
	return users, organizationUnits, nil
}
