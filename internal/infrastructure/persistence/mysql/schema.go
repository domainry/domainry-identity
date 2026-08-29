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

func (Dialect) NormalizeAuditCursorColumns(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table string, columns ...string) error {
	if len(columns) == 0 {
		return nil
	}
	physicalTable := relationPrefix + table
	placeholders := make([]string, len(columns))
	arguments := make([]any, 0, len(columns)+1)
	arguments = append(arguments, physicalTable)
	for index, column := range columns {
		placeholders[index] = renderer.Placeholder(index + 2)
		arguments = append(arguments, column)
	}
	query := "SELECT COLUMN_NAME, COLUMN_TYPE, CHARACTER_SET_NAME, COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = " + renderer.Placeholder(1) + " AND COLUMN_NAME IN (" + strings.Join(placeholders, ", ") + ")"
	rows, err := database.QueryContext(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("inspect MySQL audit cursor columns: %w", err)
	}
	type columnState struct{ columnType, characterSet, collation string }
	states := map[string]columnState{}
	for rows.Next() {
		var name string
		var state columnState
		if err := rows.Scan(&name, &state.columnType, &state.characterSet, &state.collation); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan MySQL audit cursor column: %w", err)
		}
		states[name] = state
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate MySQL audit cursor columns: %w", err)
	}
	_ = rows.Close()
	cursorType := (Dialect{}).SchemaTypes().AuditCursorText
	modifications := make([]string, 0, len(columns))
	for _, column := range columns {
		state, exists := states[column]
		if !exists {
			return fmt.Errorf("inspect MySQL audit cursor columns: %s is missing", column)
		}
		if strings.EqualFold(state.columnType, "varchar(191)") && strings.EqualFold(state.characterSet, "ascii") && strings.EqualFold(state.collation, "ascii_bin") {
			continue
		}
		modifications = append(modifications, "MODIFY COLUMN "+renderer.Identifier(column)+" "+cursorType+" NOT NULL")
	}
	if len(modifications) == 0 {
		return nil
	}
	if _, err := database.ExecContext(ctx, "ALTER TABLE "+renderer.Table(table)+" "+strings.Join(modifications, ", ")); err != nil {
		return fmt.Errorf("normalize MySQL audit cursor columns: %w", err)
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
