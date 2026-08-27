package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"

	mysqldriver "github.com/go-sql-driver/mysql"
)

type Dialect struct{}

func (Dialect) Name() string { return "mysql" }

func (Dialect) SQLDriver() string { return "mysql" }

func (Dialect) DSN(cfg config.Config) (string, error) {
	dsn := strings.TrimSpace(cfg.DatabaseDSN)
	if dsn == "" {
		return "", fmt.Errorf("DATABASE_DSN is required when DATABASE_DRIVER=mysql")
	}
	parsed, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return "", fmt.Errorf("invalid MySQL DATABASE_DSN: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(parsed.DBName), "identity") {
		return "", fmt.Errorf("MySQL DATABASE_DSN must select the identity database")
	}
	return dsn, nil
}

func (Dialect) Configure(ctx context.Context, db *sql.DB, _ string) error {
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect mysql database: %w", err)
	}
	return nil
}

func (Dialect) Identifier(value string) string {
	return database.QuoteIdentifier(value, "`")
}

func (Dialect) Placeholder(position int) string {
	return database.QuestionPlaceholder(position)
}

func (Dialect) SchemaMigrationSQL() string {
	return "CREATE TABLE IF NOT EXISTS `_schema_migrations` (`path` VARCHAR(255) PRIMARY KEY, `applied_at` VARCHAR(64) NOT NULL)"
}
