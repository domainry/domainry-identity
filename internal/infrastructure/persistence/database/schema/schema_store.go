package schema

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

// SQLDatabase is the transaction/connection-neutral DDL adapter used by the
// schema assembler. A Identity migration can provide its advisory-lock-owning
// *sql.Conn while ordinary bootstrap paths can provide *sql.DB.
type SQLDatabase interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

// Store is the schema migration persistence contract.
type Store interface {
	SchemaDB() SQLDatabase
	SchemaRenderer() ormdialect.Renderer
	DatabaseSchema() string
	Identifier(string) string
	TableIdentifier(string) string
	Placeholder(int) string
	SchemaTableExists(context.Context, string) (bool, error)
	CreateIndexIfMissing(context.Context, string, string, bool, ...string) error
	NormalizeAuditCursorColumns(context.Context, string, ...string) error
	TableColumns(context.Context, string) (map[string]bool, error)
	TableIndexes(context.Context, string) (map[string]bool, error)
	DropIndex(context.Context, string, string) error
	EnsureCompositePrimaryKey(context.Context, string, ...string) error
	MetadataIDColumnType() string
	SchemaTypes() driver.SchemaTypes
	ColumnDefinition(string) string
}

func sortedSchemaTables(tables map[string][]string) []string {
	keys := make([]string, 0, len(tables))
	for key := range tables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func quotedColumnDefinitions(store Store, definitions []string) string {
	quoted := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		parts := strings.SplitN(definition, " ", 2)
		if len(parts) == 1 {
			quoted = append(quoted, store.Identifier(parts[0]))
			continue
		}
		quoted = append(quoted, store.Identifier(parts[0])+" "+store.ColumnDefinition(parts[1]))
	}
	return strings.Join(quoted, ", ")
}

// workspaceScopedColumnDefinitions renders a fresh-schema table with its real
// Workspace-scoped primary key. Identity is not deployed yet, so its canonical
// schema must not create an installation-global key and repair the shape with a
// compatibility index afterwards.
func workspaceScopedColumnDefinitions(store Store, definitions []string) string {
	primaryKey := ""
	workspaceScoped := false
	columns := make([]string, 0, len(definitions)+1)
	for _, definition := range definitions {
		parts := strings.SplitN(definition, " ", 2)
		if len(parts) == 0 {
			continue
		}
		column := parts[0]
		workspaceScoped = workspaceScoped || column == "workspace_id"
		if strings.Contains(definition, " PRIMARY KEY") {
			primaryKey = column
			definition = strings.Replace(definition, " PRIMARY KEY", "", 1)
			if !strings.Contains(definition, " NOT NULL") {
				definition += " NOT NULL"
			}
		}
		columns = append(columns, quotedColumnDefinitions(store, []string{definition}))
	}
	if workspaceScoped && primaryKey != "" {
		columns = append(columns, "PRIMARY KEY ("+store.Identifier("workspace_id")+", "+store.Identifier(primaryKey)+")")
	}
	return strings.Join(columns, ", ")
}
