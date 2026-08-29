package postgres

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	postgresmigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres/migration"
	postgresprimarykey "github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres/primarykey"
	postgresrls "github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres/rls"
)

type engineProfile struct {
	Dialect
	driver.MigrationProfile
	driver.PrimaryKeyProfile
	driver.WorkspaceRLSProfile
}

func newEngineProfile() engineProfile {
	return engineProfile{Dialect: Dialect{}, MigrationProfile: postgresmigration.NewProfile(), PrimaryKeyProfile: postgresprimarykey.NewProfile(), WorkspaceRLSProfile: postgresrls.NewProfile()}
}

func (Dialect) EngineProfile() driver.EngineProfile { return newEngineProfile() }
