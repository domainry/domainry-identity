package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Dialect struct{}

func (Dialect) Name() string { return "postgres" }

func (Dialect) MaxParameters() int           { return 65535 }
func (Dialect) TextKeyColumnType(int) string { return "TEXT" }
func (Dialect) SchemaTypes() driver.SchemaTypes {
	return driver.SchemaTypes{Boolean: "BOOLEAN", FalseLiteral: "FALSE", DefaultText: "TEXT", DocumentText: "TEXT", IndexedText: "TEXT", AuditCursorText: "TEXT"}
}
func (Dialect) ApplyUpdateLock(builder *query.SelectBuilder) *query.SelectBuilder {
	return builder.ForUpdate()
}
func (Dialect) ApplyUpsert(builder *query.InsertBuilder, conflictColumns []string, updateColumns ...string) *query.InsertBuilder {
	assignments := make([]query.Assignment, len(updateColumns))
	for index, column := range updateColumns {
		assignments[index] = query.AssignExpression(column, query.InsertedValue(column))
	}
	return builder.OnConflictDoUpdate(conflictColumns, assignments...)
}

func (Dialect) SQLDriver() string { return "pgx" }
func (Dialect) DatabaseSchema(cfg config.Config) string {
	if schema := strings.TrimSpace(cfg.DatabaseSchema); schema != "" {
		return schema
	}
	return "public"
}

func (Dialect) DSN(cfg config.Config) (string, error) {
	if strings.TrimSpace(cfg.DatabaseDSN) == "" {
		return "", fmt.Errorf("DATABASE_DSN is required when DATABASE_DRIVER=postgres")
	}
	return strings.TrimSpace(cfg.DatabaseDSN), nil
}

func (Dialect) Configure(ctx context.Context, db *sql.DB, _ config.Config) error {
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect postgres database (%s)", ClassifyConnectionFailure(err))
	}
	return nil
}

func (Dialect) SQLDialect() ormdialect.Dialect {
	value, _ := ormdialect.New(ormdialect.Postgres)
	return value
}

func (Dialect) SchemaMigrationSQL() string {
	return `CREATE TABLE IF NOT EXISTS "_schema_migrations" ("path" TEXT PRIMARY KEY, "applied_at" TEXT NOT NULL)`
}
