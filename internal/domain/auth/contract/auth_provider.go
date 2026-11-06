package contract

import (
	"context"
	"errors"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

var (
	ErrAuthProviderInvalidCredentials = errors.New("auth provider credentials are invalid")
	ErrAuthProviderUnavailable        = errors.New("auth provider is unavailable")
)

type AuthProviderExternalIdentityWriteback interface {
	WriteAuthProviderExternalIdentity(context.Context, authmodel.AuthExternalIdentityAssertion, authmodel.AuthSession) error
}

type AuthProviderCallbackAdapter interface {
	Exchange(context.Context, string, authmodel.AuthProviderConfig, authmodel.AuthProviderChallenge, authmodel.AuthProviderCallbackInput) (authmodel.AuthExternalIdentityAssertion, error)
}

type AuthProviderCodeExchangeAdapter interface {
	ExchangeCode(context.Context, string, authmodel.AuthProviderConfig, string) (authmodel.AuthExternalIdentityAssertion, error)
}

// AuthProviderPasswordAdapter authenticates credentials directly against a
// server-side identity provider such as LDAP. The password never becomes an
// Identity user password and is never persisted by Identity.
type AuthProviderPasswordAdapter interface {
	Authenticate(context.Context, string, authmodel.AuthProviderConfig, string, string) (authmodel.AuthExternalIdentityAssertion, error)
	Probe(context.Context, authmodel.AuthProviderConfig) error
}
