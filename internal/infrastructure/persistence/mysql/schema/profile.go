package schema

import (
	"context"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormschema "github.com/domainry/domainry-orm/schema"
)

type Profile struct{}

func NewProfile() Profile { return Profile{} }

func (Profile) ManagedDatabaseMarkerEnabled() bool { return true }
func (Profile) RendererSchema(string) string       { return "" }
func (Profile) ColumnDefinition(definition string) string {
	definition = strings.TrimSpace(definition)
	// MySQL accepts defaults for TEXT/BLOB values only as expressions.
	definition = strings.ReplaceAll(definition, "TEXT NOT NULL DEFAULT '[]'", "TEXT NOT NULL DEFAULT ('[]')")
	definition = strings.ReplaceAll(definition, "TEXT NOT NULL DEFAULT '{}'", "TEXT NOT NULL DEFAULT ('{}')")
	definition = strings.ReplaceAll(definition, "TEXT NOT NULL DEFAULT ''", "TEXT NOT NULL DEFAULT ('')")
	return definition
}

// MySQL schema discovery must query information_schema. domainry-orm models
// application relations, not server catalogs, so these reads stay here.
func (Profile) ApplicationTablesQuery(ormdialect.Renderer, string) driver.SchemaQuery {
	return driver.SchemaQuery{Statement: "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()"}
}
func (Profile) WorkspaceTablesQuery(renderer ormdialect.Renderer, databaseSchema string) driver.SchemaQuery {
	return driver.SchemaQuery{
		Statement: "SELECT DISTINCT table_name FROM information_schema.columns WHERE table_schema = " + renderer.Placeholder(1) + " AND column_name = 'workspace_id' ORDER BY table_name",
		Arguments: []any{databaseSchema},
	}
}
func (Profile) TableExistsQuery(renderer ormdialect.Renderer, _ string, table string) driver.SchemaQuery {
	return driver.SchemaQuery{Statement: "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=" + renderer.Placeholder(1), Arguments: []any{table}}
}
func (profile Profile) CreateIndexIfMissing(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table, index string, unique bool, columns ...string) error {
	indexes, err := profile.TableIndexes(ctx, database, renderer, "", relationPrefix, table)
	if err != nil || indexes[index] {
		return err
	}
	builder := ormschema.NewIndex(renderer, index, table).Columns(columns...)
	if unique {
		builder.Unique()
	}
	statement, arguments, buildErr := builder.Build()
	if buildErr != nil {
		return fmt.Errorf("build MySQL index %s: %w", index, buildErr)
	}
	if _, err := database.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("create MySQL index %s: %w", index, err)
	}
	return nil
}

func (Profile) TableColumns(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table string) (map[string]bool, error) {
	rows, err := database.QueryContext(ctx, "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = "+renderer.Placeholder(1), relationPrefix+table)
	if err != nil {
		return nil, err
	}
	return mysqlNames(rows, "column")
}

func (Profile) TableIndexes(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table string) (map[string]bool, error) {
	query := "SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = " + renderer.Placeholder(1)
	rows, err := database.QueryContext(ctx, query, relationPrefix+table)
	if err != nil {
		return nil, fmt.Errorf("list MySQL indexes for %s: %w", table, err)
	}
	return mysqlNames(rows, "index")
}

func (Profile) DropIndex(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _, _, table, index string) error {
	// domainry-orm has no DROP INDEX builder, and MySQL requires the owning
	// table in this DDL form.
	_, err := database.ExecContext(ctx, "DROP INDEX "+renderer.Identifier(index)+" ON "+renderer.Table(table))
	return err
}

func (Profile) NormalizeAuditCursorColumns(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table string, columns ...string) error {
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
	cursorType := "VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin"
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
	// domainry-orm has no ALTER COLUMN builder for MySQL charset/collation
	// normalization, so this physical compatibility DDL remains dialect-local.
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
