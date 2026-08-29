package postgres

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	postgresmigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres/migration"
)

type engineProfile struct {
	Dialect
	driver.MigrationProfile
}

func newEngineProfile() engineProfile {
	return engineProfile{Dialect: Dialect{}, MigrationProfile: postgresmigration.NewProfile()}
}

func (Dialect) EngineProfile() driver.EngineProfile { return newEngineProfile() }
