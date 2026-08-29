package repository

import (
	"context"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type AuthRepository interface {
	GetIdentityCredential(context.Context, string, string) (identitymodel.IdentityCredential, bool, error)
	UpsertIdentityCredential(context.Context, string, identitymodel.IdentityCredential) error
	RecordIdentityLoginSuccess(context.Context, string, string, string) error
	CreateAuthRefreshToken(context.Context, string, identitymodel.AuthRefreshToken) error
	GetAuthRefreshTokenByHash(context.Context, string, string) (identitymodel.AuthRefreshToken, bool, error)
	RevokeAuthRefreshToken(context.Context, string, string, string, string) error
	ListAuthRefreshTokensForUser(context.Context, string, string) ([]identitymodel.AuthRefreshToken, error)
	RevokeAuthRefreshTokensForUser(context.Context, string, string, string) (int, error)
	ListIdentityExternalAccounts(context.Context, string, string) ([]identitymodel.IdentityExternalAccount, error)
	UpsertIdentityExternalAccount(context.Context, string, identitymodel.IdentityExternalAccount) error
	RemoveIdentityExternalAccount(context.Context, string, string) error
}

type AuthMutationRepository interface {
	TryBeginAuthMutation(context.Context, string, authmodel.AuthMutationClaimRequest) (authmodel.AuthMutationClaimResult, error)
	CompleteAuthMutation(context.Context, string, authmodel.AuthMutationCompletion) (authmodel.AuthMutationReceipt, error)
}

const (
	AuthSessionStateMissing = "missing"
	AuthSessionStateActive  = "active"
	AuthSessionStateRevoked = "revoked"
	AuthSessionStateExpired = "expired"
)

// AuthSessionRepository is the durable authority for logical login sessions.
// A logical session keeps the same session ID while refresh tokens rotate.
type AuthSessionRepository interface {
	AuthSessionState(context.Context, string, string, string, time.Time) (string, error)
	RevokeOtherAuthSessions(context.Context, string, string, string, string) (int, error)
	RevokeAuthSession(context.Context, string, string, string, string) (int, error)
}

// AuthRefreshRotationRepository atomically consumes one active refresh token
// and inserts its replacement in the same database transaction. A false result
// means another caller already consumed the old token.
type AuthRefreshRotationRepository interface {
	RotateAuthRefreshToken(context.Context, string, string, string, identitymodel.AuthRefreshToken) (bool, error)
}

// AuthLoginAttemptRepository owns the atomic failed-login counter update. The
// password verifier must not implement lockout as a read-modify-upsert because
// concurrent failures could overwrite one another and avoid the lock threshold.
type AuthLoginAttemptRepository interface {
	RecordIdentityLoginFailure(context.Context, string, string, int, string, string) error
}

type AuthProviderCredentialRepository interface {
	ListAuthProviderCredentials(context.Context, string) ([]authmodel.AuthProviderCredential, error)
}

// AuthLoginTransactionRepository persists secret-bearing, one-time external
// login state. Consume must be atomic across processes and replicas.
type AuthLoginTransactionRepository interface {
	CreateAuthLoginTransaction(context.Context, authmodel.AuthProviderChallenge) error
	ConsumeAuthLoginTransaction(context.Context, string, string, string, time.Time) (authmodel.AuthProviderChallenge, bool, error)
}

// AuthOTPTransactionRepository owns both delivery throttling and verification
// attempts across replicas while keeping the phone and code encrypted at rest.
// Create returns false when the subject is still inside its delivery cooldown.
// A non-empty consumed challenge with valid=false represents a wrong code; an
// empty challenge represents invalid state.
type AuthOTPTransactionRepository interface {
	CreateAuthOTPTransaction(context.Context, authmodel.AuthProviderChallenge, string, time.Time, time.Time) (bool, error)
	ConsumeAuthOTPTransaction(context.Context, string, string, string, string, int, time.Time) (authmodel.AuthProviderChallenge, bool, error)
}

// AuthAuthorizationCodeRepository owns the short-lived handoff from the
// Identity provider callback to a Runtime browser gateway. Codes are hashed at
// rest and atomically consumed once.
type AuthAuthorizationCodeRepository interface {
	CreateAuthAuthorizationCode(context.Context, authmodel.AuthAuthorizationCode) error
	ConsumeAuthAuthorizationCode(context.Context, string, string, string, string, time.Time) (authmodel.AuthSession, bool, error)
}

type AuthApplicationRepository interface {
	AuthorizationRedirectRegistered(context.Context, string, string, string) (bool, error)
}

// AuthAssertionReplayRepository atomically records an external identity
// assertion. A false result means the same signed assertion was already used.
type AuthAssertionReplayRepository interface {
	ClaimAuthAssertion(context.Context, string, string, string, string, time.Time) (bool, error)
}

type AuthMFARepository interface {
	ListIdentityMFAFactors(context.Context, string, string) ([]identitymodel.IdentityMFAFactor, error)
	UpsertIdentityMFAFactor(context.Context, string, identitymodel.IdentityMFAFactor) error
	RevokeIdentityMFAFactor(context.Context, string, string, string) error
}

type AuthUserDirectorySecurityRepository interface {
	ListUserDirectorySecurityFacts(context.Context, string, []string) ([]authmodel.UserDirectorySecurityFact, error)
}
