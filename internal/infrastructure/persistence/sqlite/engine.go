package sqlite

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	sqlitemigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/migration"
	sqliteprimarykey "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/primarykey"
	sqliterls "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/rls"
	sqliteschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/schema"
)

type engineProfile struct {
	Dialect
	driver.MigrationProfile
	driver.PrimaryKeyProfile
	driver.WorkspaceRLSProfile
	driver.SchemaProfile
}

func newEngineProfile() engineProfile {
	return engineProfile{Dialect: Dialect{}, MigrationProfile: sqlitemigration.NewProfile(), PrimaryKeyProfile: sqliteprimarykey.NewProfile(), WorkspaceRLSProfile: sqliterls.NewProfile(), SchemaProfile: sqliteschema.NewProfile()}
}

func (Dialect) EngineProfile() driver.EngineProfile { return newEngineProfile() }
