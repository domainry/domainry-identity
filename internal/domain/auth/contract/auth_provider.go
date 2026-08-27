package contract

import (
	"context"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

type AuthProviderExternalIdentityWriteback interface {
	WriteAuthProviderExternalIdentity(context.Context, authmodel.AuthExternalIdentityAssertion, authmodel.AuthSession) error
}

type AuthProviderCallbackAdapter interface {
	Exchange(context.Context, string, authmodel.AuthProviderConfig, authmodel.AuthProviderChallenge, authmodel.AuthProviderCallbackInput) (authmodel.AuthExternalIdentityAssertion, error)
}
