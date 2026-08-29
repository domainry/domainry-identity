package postgres

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	postgresmigration "github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres/migration"
	postgresprimarykey "github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres/primarykey"
	postgresrls "github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres/rls"
	postgresschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres/schema"
)

type Engine struct {
	Dialect
	driver.MigrationProfile
	driver.PrimaryKeyProfile
	driver.WorkspaceRLSProfile
	driver.SchemaProfile
}

func NewEngine() Engine {
	return Engine{Dialect: Dialect{}, MigrationProfile: postgresmigration.NewProfile(), PrimaryKeyProfile: postgresprimarykey.NewProfile(), WorkspaceRLSProfile: postgresrls.NewProfile(), SchemaProfile: postgresschema.NewProfile()}
}
