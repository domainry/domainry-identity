package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (Dialect) MigrationLedgerTypes() driver.MigrationLedgerTypes {
	return driver.MigrationLedgerTypes{Key: "TEXT", Timestamp: "TEXT"}
}
func (Dialect) EnsureMigrationNamespace(context.Context, driver.SchemaDatabase, ormdialect.Renderer, string) error {
	return nil
}
func (Dialect) ConfigureMigrationTransaction(context.Context, *sql.Tx, ormdialect.Renderer, string, time.Duration, time.Duration) error {
	return nil
}

func (Dialect) MigrationDatabasePath(cfg config.Config) string {
	if value := strings.TrimSpace(cfg.DBPath); value != "" {
		return value
	}
	return strings.TrimSpace(cfg.DatabaseDSN)
}
