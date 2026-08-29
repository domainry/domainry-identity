package mysql

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	mysqlmigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/migration"
)

type engineProfile struct {
	Dialect
	driver.MigrationProfile
}

func newEngineProfile() engineProfile {
	return engineProfile{Dialect: Dialect{}, MigrationProfile: mysqlmigration.NewProfile()}
}

func (Dialect) EngineProfile() driver.EngineProfile { return newEngineProfile() }
