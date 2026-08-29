package sqlite

import (
	"strings"

	"github.com/domainry/domainry-identity/internal/platform/config"
)

func (Dialect) MigrationDatabasePath(cfg config.Config) string {
	if value := strings.TrimSpace(cfg.DBPath); value != "" {
		return value
	}
	return strings.TrimSpace(cfg.DatabaseDSN)
}
