package sqlite

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	sqlitemigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/migration"
	sqliteprimarykey "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/primarykey"
	sqliterls "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/rls"
	sqliteschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/schema"
)

type Engine struct {
	Dialect
	driver.MigrationProfile
	driver.PrimaryKeyProfile
	driver.WorkspaceRLSProfile
	driver.SchemaProfile
}

func NewEngine() Engine {
	return Engine{Dialect: Dialect{}, MigrationProfile: sqlitemigration.NewProfile(), PrimaryKeyProfile: sqliteprimarykey.NewProfile(), WorkspaceRLSProfile: sqliterls.NewProfile(), SchemaProfile: sqliteschema.NewProfile()}
}
