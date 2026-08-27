package identity

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitydomain "github.com/domainry/domainry-identity/internal/domain/identity/service"
)

type IdentityPrincipalDependencies struct {
	Roles          func() []identitymodel.RoleSchema
	DefaultRoleKey func() string
}

// IdentityPrincipalApplicationService resolves Runtime principals from the
// Identity role snapshot supplied by the caller.
type IdentityPrincipalApplicationService struct {
	*identitydomain.IdentityPrincipalDomainService
}

func NewIdentityPrincipalApplicationService(dependencies IdentityPrincipalDependencies) *IdentityPrincipalApplicationService {
	return &IdentityPrincipalApplicationService{IdentityPrincipalDomainService: identitydomain.NewIdentityPrincipalDomainService(dependencies.Roles, dependencies.DefaultRoleKey)}
}
