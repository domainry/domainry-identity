package mysql

import (
	"context"
	"database/sql"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (Dialect) MigrationLedgerTypes() driver.MigrationLedgerTypes {
	return driver.MigrationLedgerTypes{Key: "VARCHAR(255)", Timestamp: "VARCHAR(64)"}
}
func (Dialect) EnsureMigrationNamespace(context.Context, driver.SchemaDatabase, ormdialect.Renderer, string) error {
	return nil
}
func (Dialect) ConfigureMigrationTransaction(context.Context, *sql.Tx, ormdialect.Renderer, string, time.Duration, time.Duration) error {
	return nil
}

func (Dialect) MigrationDatabasePath(config.Config) string { return "" }
