package sqlite

import (
	"context"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (Dialect) CreateIndexIfMissing(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table, index string, unique bool, columns ...string) error {
	physicalTable := relationPrefix + table
	rows, err := database.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = "+renderer.Placeholder(1), physicalTable)
	if err != nil {
		return fmt.Errorf("list SQLite indexes for %s: %w", table, err)
	}
	exists, err := sqliteIndexExists(rows, index)
	if err != nil || exists {
		return err
	}
	prefix := "CREATE INDEX IF NOT EXISTS "
	if unique {
		prefix = "CREATE UNIQUE INDEX IF NOT EXISTS "
	}
	if _, err := database.ExecContext(ctx, prefix+renderer.Identifier(index)+" ON "+renderer.Table(table)+" ("+schemaColumnList(renderer, columns)+")"); err != nil {
		return fmt.Errorf("create SQLite index %s: %w", index, err)
	}
	return nil
}

func sqliteIndexExists(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}, index string) (bool, error) {
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, fmt.Errorf("scan SQLite index: %w", err)
		}
		if name == index {
			return true, nil
		}
	}
	return false, rows.Err()
}

func schemaColumnList(renderer ormdialect.Renderer, columns []string) string {
	quoted := make([]string, len(columns))
	for index, column := range columns {
		quoted[index] = renderer.Identifier(column)
	}
	return strings.Join(quoted, ", ")
}
