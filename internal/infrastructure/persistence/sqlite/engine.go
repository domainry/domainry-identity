package sqlite

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	sqlitemigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/migration"
)

type engineProfile struct {
	Dialect
	driver.MigrationProfile
}

func newEngineProfile() engineProfile {
	return engineProfile{Dialect: Dialect{}, MigrationProfile: sqlitemigration.NewProfile()}
}

func (Dialect) EngineProfile() driver.EngineProfile { return newEngineProfile() }
