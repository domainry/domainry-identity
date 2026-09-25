package auth

import (
	"encoding/json"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

// The auth models are also used by the API. Keep their string timestamps out of
// durable, encrypted JSON by projecting the owned instants before serialization.
type persistedAuthProviderChallenge struct {
	authmodel.AuthProviderChallenge
	RetryAt   int64 `json:"retry_at,omitempty"`
	ExpiresAt int64 `json:"expires_at"`
	CreatedAt int64 `json:"created_at"`
}

func marshalPersistedAuthProviderChallenge(value authmodel.AuthProviderChallenge) ([]byte, error) {
	return json.Marshal(persistedAuthProviderChallenge{
		AuthProviderChallenge: value,
		RetryAt:               identitypersistence.TimeMillis(value.RetryAt),
		ExpiresAt:             identitypersistence.TimeMillis(value.ExpiresAt),
		CreatedAt:             identitypersistence.TimeMillis(value.CreatedAt),
	})
}

func unmarshalPersistedAuthProviderChallenge(raw []byte) (authmodel.AuthProviderChallenge, error) {
	var stored persistedAuthProviderChallenge
	if err := json.Unmarshal(raw, &stored); err != nil {
		return authmodel.AuthProviderChallenge{}, err
	}
	value := stored.AuthProviderChallenge
	value.RetryAt = identitypersistence.TimeString(stored.RetryAt)
	value.ExpiresAt = identitypersistence.TimeString(stored.ExpiresAt)
	value.CreatedAt = identitypersistence.TimeString(stored.CreatedAt)
	return value, nil
}

type persistedAuthSession struct {
	authmodel.AuthSession
	ExpiresAt int64 `json:"expires_at"`
}

func marshalPersistedAuthSession(value authmodel.AuthSession) ([]byte, error) {
	return json.Marshal(persistedAuthSession{
		AuthSession: value,
		ExpiresAt:   identitypersistence.TimeMillis(value.ExpiresAt),
	})
}

func unmarshalPersistedAuthSession(raw []byte) (authmodel.AuthSession, error) {
	var stored persistedAuthSession
	if err := json.Unmarshal(raw, &stored); err != nil {
		return authmodel.AuthSession{}, err
	}
	value := stored.AuthSession
	value.ExpiresAt = identitypersistence.TimeString(stored.ExpiresAt)
	return value, nil
}
