package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (Dialect) CreateIndexIfMissing(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, databaseSchema, relationPrefix, table, index string, unique bool, columns ...string) error {
	physicalTable := relationPrefix + table
	query := "SELECT indexname FROM pg_indexes WHERE schemaname = " + renderer.Placeholder(1) + " AND tablename = " + renderer.Placeholder(2)
	rows, err := database.QueryContext(ctx, query, databaseSchema, physicalTable)
	if err != nil {
		return fmt.Errorf("list PostgreSQL indexes for %s: %w", table, err)
	}
	exists, err := postgresIndexExists(rows, index)
	if err != nil || exists {
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

func postgresIndexExists(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}, index string) (bool, error) {
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, fmt.Errorf("scan PostgreSQL index: %w", err)
		}
		if name == index {
			return true, nil
		}
	}
	return false, rows.Err()
}

func postgresSchemaColumnList(renderer ormdialect.Renderer, columns []string) string {
	quoted := make([]string, len(columns))
	for index, column := range columns {
		quoted[index] = renderer.Identifier(column)
	}
	return strings.Join(quoted, ", ")
}
