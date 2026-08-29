package sqlite

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	sqlitemigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/migration"
	sqliteprimarykey "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/primarykey"
	sqliterls "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite/rls"
)

type engineProfile struct {
	Dialect
	driver.MigrationProfile
	driver.PrimaryKeyProfile
	driver.WorkspaceRLSProfile
}

func newEngineProfile() engineProfile {
	return engineProfile{Dialect: Dialect{}, MigrationProfile: sqlitemigration.NewProfile(), PrimaryKeyProfile: sqliteprimarykey.NewProfile(), WorkspaceRLSProfile: sqliterls.NewProfile()}
}

func (Dialect) EngineProfile() driver.EngineProfile { return newEngineProfile() }
