package database

import (
	"github.com/domainry/domainry-foundation/secrets"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/connection"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
)

type databaseEngine = driver.Engine

type identityOpenDependencies struct {
	engine     func(string) (databaseEngine, error)
	connection connection.Dependencies
	keyRing    func(secrets.Key, ...secrets.Key) (secrets.KeyProvider, error)
}

func defaultIdentityOpenDependencies() identityOpenDependencies {
	return identityOpenDependencies{
		engine:     connection.EngineFor,
		connection: connection.DefaultDependencies(),
		keyRing: func(active secrets.Key, decryptOnly ...secrets.Key) (secrets.KeyProvider, error) {
			return secrets.NewMemoryKeyRing(active, decryptOnly...)
		},
	}
}
