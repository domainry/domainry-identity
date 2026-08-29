package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (Dialect) ManagedDatabaseMarkerEnabled() bool        { return true }
func (Dialect) ColumnDefinition(definition string) string { return strings.TrimSpace(definition) }

func (Dialect) CreateIndexIfMissing(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, databaseSchema, relationPrefix, table, index string, unique bool, columns ...string) error {
	indexes, err := (Dialect{}).TableIndexes(ctx, database, renderer, databaseSchema, relationPrefix, table)
	if err != nil || indexes[index] {
		return err
	}
	prefix := "CREATE INDEX IF NOT EXISTS "
	if unique {
		prefix = "CREATE UNIQUE INDEX IF NOT EXISTS "
	}
	if _, err := database.ExecContext(ctx, prefix+renderer.Identifier(index)+" ON "+renderer.Table(table)+" ("+postgresSchemaColumnList(renderer, columns)+")"); err != nil {
		return fmt.Errorf("create PostgreSQL index %s: %w", index, err)
	}
	return nil
}

func (Dialect) TableColumns(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, databaseSchema, relationPrefix, table string) (map[string]bool, error) {
	query := "SELECT column_name FROM information_schema.columns WHERE table_schema = " + renderer.Placeholder(1) + " AND table_name = " + renderer.Placeholder(2)
	rows, err := database.QueryContext(ctx, query, databaseSchema, relationPrefix+table)
	if err != nil {
		return nil, err
	}
	return postgresNames(rows, "column")
}

func (Dialect) TableIndexes(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, databaseSchema, relationPrefix, table string) (map[string]bool, error) {
	query := "SELECT indexname FROM pg_indexes WHERE schemaname = " + renderer.Placeholder(1) + " AND tablename = " + renderer.Placeholder(2)
	rows, err := database.QueryContext(ctx, query, databaseSchema, relationPrefix+table)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL indexes for %s: %w", table, err)
	}
	return postgresNames(rows, "index")
}

func (Dialect) DropIndex(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _, _, _, index string) error {
	_, err := database.ExecContext(ctx, "DROP INDEX IF EXISTS "+renderer.Identifier(index))
	return err
}

func (Dialect) NormalizeAuditCursorColumns(context.Context, driver.SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error {
	return nil
}

func postgresNames(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}, kind string) (map[string]bool, error) {
	defer rows.Close()
	values := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan PostgreSQL %s: %w", kind, err)
		}
		values[name] = true
	}
	return values, rows.Err()
}

func postgresSchemaColumnList(renderer ormdialect.Renderer, columns []string) string {
	quoted := make([]string, len(columns))
	for index, column := range columns {
		quoted[index] = renderer.Identifier(column)
	}
	return strings.Join(quoted, ", ")
}
