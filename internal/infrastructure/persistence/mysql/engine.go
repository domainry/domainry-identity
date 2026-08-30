package mysql

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	mysqlmigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/migration"
	mysqlprimarykey "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/primarykey"
	mysqlschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql/schema"
)

type Engine struct {
	Dialect
	driver.MigrationProfile
	driver.PrimaryKeyProfile
	driver.SchemaProfile
}

func NewEngine() Engine {
	return Engine{Dialect: Dialect{}, MigrationProfile: mysqlmigration.NewProfile(), PrimaryKeyProfile: mysqlprimarykey.NewProfile(), SchemaProfile: mysqlschema.NewProfile()}
}
