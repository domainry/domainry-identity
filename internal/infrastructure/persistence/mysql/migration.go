package mysql

import "github.com/domainry/domainry-identity/internal/platform/config"

func (Dialect) MigrationDatabasePath(config.Config) string { return "" }
