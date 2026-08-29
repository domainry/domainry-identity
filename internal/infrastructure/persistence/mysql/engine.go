package mysql

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	mysqlmigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/migration"
	mysqlprimarykey "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/primarykey"
	mysqlrls "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/rls"
)

type engineProfile struct {
	Dialect
	driver.MigrationProfile
	driver.PrimaryKeyProfile
	driver.WorkspaceRLSProfile
}

func newEngineProfile() engineProfile {
	return engineProfile{Dialect: Dialect{}, MigrationProfile: mysqlmigration.NewProfile(), PrimaryKeyProfile: mysqlprimarykey.NewProfile(), WorkspaceRLSProfile: mysqlrls.NewProfile()}
}

func (Dialect) EngineProfile() driver.EngineProfile { return newEngineProfile() }
