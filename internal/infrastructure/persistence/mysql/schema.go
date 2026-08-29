package mysql

import (
	"context"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (Dialect) ManagedDatabaseMarkerEnabled() bool { return true }
func (Dialect) ColumnDefinition(definition string) string {
	definition = strings.TrimSpace(definition)
	// MySQL accepts defaults for TEXT/BLOB values only as expressions.
	definition = strings.ReplaceAll(definition, "TEXT NOT NULL DEFAULT '[]'", "TEXT NOT NULL DEFAULT ('[]')")
	definition = strings.ReplaceAll(definition, "TEXT NOT NULL DEFAULT '{}'", "TEXT NOT NULL DEFAULT ('{}')")
	definition = strings.ReplaceAll(definition, "TEXT NOT NULL DEFAULT ''", "TEXT NOT NULL DEFAULT ('')")
	return definition
}
func (Dialect) ApplicationTablesQuery(ormdialect.Renderer, string) driver.SchemaQuery {
	return driver.SchemaQuery{Statement: "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()"}
}
func (Dialect) WorkspaceTablesQuery(renderer ormdialect.Renderer, databaseSchema string) driver.SchemaQuery {
	return driver.SchemaQuery{
		Statement: "SELECT DISTINCT table_name FROM information_schema.columns WHERE table_schema = " + renderer.Placeholder(1) + " AND column_name = 'workspace_id' ORDER BY table_name",
		Arguments: []any{databaseSchema},
	}
}

func (Dialect) CreateIndexIfMissing(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table, index string, unique bool, columns ...string) error {
	indexes, err := (Dialect{}).TableIndexes(ctx, database, renderer, "", relationPrefix, table)
	if err != nil || indexes[index] {
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

func (Dialect) TableColumns(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table string) (map[string]bool, error) {
	rows, err := database.QueryContext(ctx, "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = "+renderer.Placeholder(1), relationPrefix+table)
	if err != nil {
		return nil, err
	}
	return mysqlNames(rows, "column")
}

func (Dialect) TableIndexes(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table string) (map[string]bool, error) {
	query := "SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = " + renderer.Placeholder(1)
	rows, err := database.QueryContext(ctx, query, relationPrefix+table)
	if err != nil {
		return nil, fmt.Errorf("list MySQL indexes for %s: %w", table, err)
	}
	return mysqlNames(rows, "index")
}

func (Dialect) DropIndex(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _, _, table, index string) error {
	_, err := database.ExecContext(ctx, "DROP INDEX "+renderer.Identifier(index)+" ON "+renderer.Table(table))
	return err
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

func mysqlNames(rows interface {
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
			return nil, fmt.Errorf("scan MySQL %s: %w", kind, err)
		}
		values[name] = true
	}
	return values, rows.Err()
}

func mysqlSchemaColumnList(renderer ormdialect.Renderer, columns []string) string {
	quoted := make([]string, len(columns))
	for index, column := range columns {
		quoted[index] = renderer.Identifier(column)
	}
	return strings.Join(quoted, ", ")
}
