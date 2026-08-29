package driver

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/domainry/domainry-identity/internal/platform/config"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

// Dialect combines the shared SQL renderer with Identity-owned connection and
// migration configuration. Generic rendering lives in domainry-orm.
type Dialect interface {
	Name() string
	SQLDriver() string
	DSN(config.Config) (string, error)
	Configure(context.Context, *sql.DB, string) error
	SQLDialect() ormdialect.Dialect
	SchemaMigrationSQL() string
}

type EngineProfile interface {
	MaxParameters() int
	TextKeyColumnType(int) string
	SchemaTypes() SchemaTypes
	ApplyUpdateLock(*ormbuilder.SelectBuilder) *ormbuilder.SelectBuilder
	ApplyUpsert(*ormbuilder.InsertBuilder, []string, ...string) *ormbuilder.InsertBuilder
	CreateIndexIfMissing(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, string, bool, ...string) error
	NormalizeAuditCursorColumns(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error
	EnsureCompositePrimaryKey(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error
}

type SchemaTypes struct {
	Boolean         string
	FalseLiteral    string
	DefaultText     string
	DocumentText    string
	IndexedText     string
	AuditCursorText string
}

type SchemaDatabase interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

type portableEngineProfile struct{}

func (portableEngineProfile) MaxParameters() int           { return 999 }
func (portableEngineProfile) TextKeyColumnType(int) string { return "TEXT" }
func (portableEngineProfile) SchemaTypes() SchemaTypes {
	return SchemaTypes{Boolean: "BOOLEAN", FalseLiteral: "FALSE", DefaultText: "TEXT", DocumentText: "TEXT", IndexedText: "TEXT", AuditCursorText: "TEXT"}
}
func (portableEngineProfile) ApplyUpdateLock(builder *ormbuilder.SelectBuilder) *ormbuilder.SelectBuilder {
	return builder
}
func (portableEngineProfile) ApplyUpsert(builder *ormbuilder.InsertBuilder, conflictColumns []string, updateColumns ...string) *ormbuilder.InsertBuilder {
	assignments := make([]ormbuilder.Assignment, len(updateColumns))
	for index, column := range updateColumns {
		assignments[index] = ormbuilder.AssignExpression(column, ormbuilder.InsertedValue(column))
	}
	return builder.OnConflictDoUpdate(conflictColumns, assignments...)
}
func (portableEngineProfile) CreateIndexIfMissing(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, string, bool, ...string) error {
	return fmt.Errorf("database engine does not support index creation")
}
func (portableEngineProfile) NormalizeAuditCursorColumns(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error {
	return nil
}
func (portableEngineProfile) EnsureCompositePrimaryKey(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error {
	return fmt.Errorf("database engine does not support composite primary-key migration")
}

func ProfileFor(value Dialect) EngineProfile {
	if profile, ok := value.(EngineProfile); ok {
		return profile
	}
	return portableEngineProfile{}
}
