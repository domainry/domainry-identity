package mysql

import (
	"context"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (Dialect) CreateIndexIfMissing(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table, index string, unique bool, columns ...string) error {
	physicalTable := relationPrefix + table
	query := "SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = " + renderer.Placeholder(1)
	rows, err := database.QueryContext(ctx, query, physicalTable)
	if err != nil {
		return fmt.Errorf("list MySQL indexes for %s: %w", table, err)
	}
	exists, err := mysqlIndexExists(rows, index)
	if err != nil || exists {
		return err
	}
	prefix := "CREATE INDEX "
	if unique {
		prefix = "CREATE UNIQUE INDEX "
	}
	if _, err := database.ExecContext(ctx, prefix+renderer.Identifier(index)+" ON "+renderer.Table(table)+" ("+mysqlSchemaColumnList(renderer, columns)+")"); err != nil {
		return fmt.Errorf("create MySQL index %s: %w", index, err)
	}
	return nil
}

func mysqlIndexExists(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}, index string) (bool, error) {
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, fmt.Errorf("scan MySQL index: %w", err)
		}
		if name == index {
			return true, nil
		}
	}
	return false, rows.Err()
}

func mysqlSchemaColumnList(renderer ormdialect.Renderer, columns []string) string {
	quoted := make([]string, len(columns))
	for index, column := range columns {
		quoted[index] = renderer.Identifier(column)
	}
	return strings.Join(quoted, ", ")
}
