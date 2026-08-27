package auth

import (
	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
)

type AuthProviderFlowApplicationService struct {
	*authdomain.AuthProviderFlowDomainService
}

func NewAuthProviderFlowApplicationService(auth *AuthApplicationService, providers *AuthProviderApplicationService, writebacks ...authcontract.AuthProviderExternalIdentityWriteback) *AuthProviderFlowApplicationService {
	var owner *authdomain.AuthDomainService
	if auth != nil {
		owner = auth.AuthDomainService
	}
	var providerOwner *authdomain.AuthProviderDomainService
	if providers != nil {
		providerOwner = providers.AuthProviderDomainService
	}
	return &AuthProviderFlowApplicationService{AuthProviderFlowDomainService: authdomain.NewAuthProviderFlowDomainService(owner, providerOwner, writebacks...)}
}
