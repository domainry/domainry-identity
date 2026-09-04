package schema

import (
	"context"
	"testing"

	persistencedriver "github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type schemaHelperStore struct{}

func (schemaHelperStore) SchemaDB() SQLDatabase { return nil }
func (schemaHelperStore) SchemaRenderer() ormdialect.Renderer {
	dialect, _ := ormdialect.New(ormdialect.SQLite)
	return dialect.WithSchema("")
}
func (schemaHelperStore) MaxParameters() int     { return 999 }
func (schemaHelperStore) Driver() string         { return "sqlite" }
func (schemaHelperStore) DatabaseSchema() string { return "" }
func (schemaHelperStore) Identifier(value string) string {
	return `"` + value + `"`
}
func (schemaHelperStore) TableIdentifier(value string) string                     { return value }
func (schemaHelperStore) Placeholder(index int) string                            { return "?" }
func (schemaHelperStore) SchemaTableExists(context.Context, string) (bool, error) { return false, nil }
func (schemaHelperStore) CreateIndexIfMissing(context.Context, string, string, bool, ...string) error {
	return nil
}
func (schemaHelperStore) NormalizeAuditCursorColumns(context.Context, string, ...string) error {
	return nil
}
func (schemaHelperStore) TableColumns(context.Context, string) (map[string]bool, error) {
	return map[string]bool{}, nil
}
func (schemaHelperStore) TableIndexes(context.Context, string) (map[string]bool, error) {
	return map[string]bool{}, nil
}
func (schemaHelperStore) DropIndex(context.Context, string, string) error { return nil }
func (schemaHelperStore) EnsureCompositePrimaryKey(context.Context, string, ...string) error {
	return nil
}
func (schemaHelperStore) MetadataIDColumnType() string       { return "TEXT" }
func (schemaHelperStore) LocalizedTextKeyColumnType() string { return "TEXT" }
func (schemaHelperStore) SchemaTypes() persistencedriver.SchemaTypes {
	return persistencedriver.SchemaTypes{Boolean: "INTEGER", FalseLiteral: "0", DefaultText: "TEXT", DocumentText: "TEXT", IndexedText: "TEXT", AuditCursorText: "TEXT"}
}
func (schemaHelperStore) ColumnDefinition(value string) string {
	return "normalized:" + value
}

func TestSchemaHelperQuotedColumnDefinitions(t *testing.T) {
	if got := quotedColumnDefinitions(schemaHelperStore{}, []string{"id", "name TEXT NOT NULL"}); got != `"id", "name" normalized:TEXT NOT NULL` {
		t.Fatalf("quoted definitions=%q", got)
	}
}

var _ Store = schemaHelperStore{}
