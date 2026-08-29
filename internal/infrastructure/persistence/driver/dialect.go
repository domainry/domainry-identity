package driver

import (
	"context"
	"database/sql"

	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

// Dialect combines the shared SQL renderer with Identity-owned connection and
// migration configuration. Generic rendering lives in domainry-orm.
type Dialect interface {
	Name() string
	SQLDriver() string
	DSN(config.Config) (string, error)
	Configure(context.Context, *sql.DB, string) error
	SQLDialect() ormdialect.Dialect
	SchemaMigrationSQL() string
}
