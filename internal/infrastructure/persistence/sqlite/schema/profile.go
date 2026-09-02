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

func (Profile) ManagedDatabaseMarkerEnabled() bool        { return false }
func (Profile) ColumnDefinition(definition string) string { return strings.TrimSpace(definition) }
func (Profile) RendererSchema(string) string              { return "" }

// SQLite schema discovery must query sqlite_master/PRAGMA. domainry-orm does
// not model database catalogs, so these read-only statements stay here.
func (Profile) ApplicationTablesQuery(ormdialect.Renderer, string) driver.SchemaQuery {
	return driver.SchemaQuery{Statement: "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"}
}
func (Profile) WorkspaceTablesQuery(ormdialect.Renderer, string) driver.SchemaQuery {
	return driver.SchemaQuery{Statement: "SELECT DISTINCT m.name FROM sqlite_master m JOIN pragma_table_info(m.name) p WHERE m.type = 'table' AND p.name = 'workspace_id' ORDER BY m.name"}
}
func (Profile) TableExistsQuery(renderer ormdialect.Renderer, _ string, table string) driver.SchemaQuery {
	return driver.SchemaQuery{Statement: "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=" + renderer.Placeholder(1), Arguments: []any{table}}
}
func (profile Profile) CreateIndexIfMissing(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table, index string, unique bool, columns ...string) error {
	indexes, err := profile.TableIndexes(ctx, database, renderer, "", relationPrefix, table)
	if err != nil || indexes[index] {
		return err
	}
	builder := ormschema.NewIndex(renderer, index, table).Columns(columns...).IfNotExists()
	if unique {
		builder.Unique()
	}
	statement, arguments, buildErr := builder.Build()
	if buildErr != nil {
		return fmt.Errorf("build SQLite index %s: %w", index, buildErr)
	}
	if _, err := database.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("create SQLite index %s: %w", index, err)
	}
	return nil
}

func (Profile) TableColumns(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table string) (map[string]bool, error) {
	rows, err := database.QueryContext(ctx, "PRAGMA table_info("+renderer.Identifier(relationPrefix+table)+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

func (Profile) TableIndexes(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _ string, relationPrefix, table string) (map[string]bool, error) {
	physicalTable := relationPrefix + table
	rows, err := database.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = "+renderer.Placeholder(1), physicalTable)
	if err != nil {
		return nil, fmt.Errorf("list SQLite indexes for %s: %w", table, err)
	}
	return sqliteIndexNames(rows)
}

func (Profile) DropIndex(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _, _, _, index string) error {
	// domainry-orm has no DROP INDEX builder; keep this quoted dialect DDL in
	// the SQLite schema adapter.
	_, err := database.ExecContext(ctx, "DROP INDEX IF EXISTS "+renderer.Identifier(index))
	return err
}

func (Profile) NormalizeAuditCursorColumns(context.Context, driver.SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error {
	return nil
}

func sqliteIndexNames(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}) (map[string]bool, error) {
	defer rows.Close()
	indexes := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan SQLite index: %w", err)
		}
		indexes[name] = true
	}
	return indexes, rows.Err()
}
