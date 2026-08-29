package mysql

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	mysqlmigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/migration"
	mysqlprimarykey "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/primarykey"
	mysqlrls "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/rls"
	mysqlschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/schema"
)

type engineProfile struct {
	Dialect
	driver.MigrationProfile
	driver.PrimaryKeyProfile
	driver.WorkspaceRLSProfile
	driver.SchemaProfile
}

func newEngineProfile() engineProfile {
	return engineProfile{Dialect: Dialect{}, MigrationProfile: mysqlmigration.NewProfile(), PrimaryKeyProfile: mysqlprimarykey.NewProfile(), WorkspaceRLSProfile: mysqlrls.NewProfile(), SchemaProfile: mysqlschema.NewProfile()}
}

func (Dialect) EngineProfile() driver.EngineProfile { return newEngineProfile() }
