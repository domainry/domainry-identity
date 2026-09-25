package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"

	mysqldriver "github.com/go-sql-driver/mysql"
)

type Dialect struct{}

func (Dialect) Name() string { return "mysql" }

func (Dialect) MaxParameters() int                     { return 65535 }
func (Dialect) TextKeyColumnType(maxLength int) string { return fmt.Sprintf("VARCHAR(%d)", maxLength) }
func (Dialect) SchemaTypes() driver.SchemaTypes {
	return driver.SchemaTypes{
		Boolean: "BOOLEAN", FalseLiteral: "0", DefaultText: "VARCHAR(255)", DocumentText: "LONGTEXT",
		IndexedText:     "VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin",
		AuditCursorText: "VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin",
	}
}
func (Dialect) ApplyUpdateLock(builder *query.SelectBuilder) *query.SelectBuilder {
	return builder.ForUpdate()
}
func (Dialect) ApplyUpsert(builder *query.InsertBuilder, _ []string, updateColumns ...string) *query.InsertBuilder {
	assignments := make([]query.Assignment, len(updateColumns))
	for index, column := range updateColumns {
		assignments[index] = query.AssignExpression(column, query.InsertedValue(column))
	}
	return builder.OnDuplicateKeyUpdate(assignments...)
}

func (Dialect) SQLDriver() string                   { return "mysql" }
func (Dialect) DatabaseSchema(config.Config) string { return "" }

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

func (Dialect) Configure(ctx context.Context, db *sql.DB, _ config.Config) error {
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect mysql database: %w", err)
	}
	return nil
}

func (Dialect) SQLDialect() ormdialect.Dialect {
	value, _ := ormdialect.New(ormdialect.MySQL)
	return value
}

func (Dialect) SchemaMigrationSQL() string {
	return "CREATE TABLE IF NOT EXISTS `_schema_migrations` (`path` VARCHAR(255) PRIMARY KEY, `applied_at` BIGINT NOT NULL)"
}
