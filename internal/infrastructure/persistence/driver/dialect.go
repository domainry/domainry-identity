package driver

import (
	"context"
	"database/sql"
	"time"

	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

// Dialect combines the shared SQL renderer with Identity-owned connection and
// migration configuration. Generic rendering lives in domainry-orm.
type Dialect interface {
	Name() string
	SQLDriver() string
	DSN(config.Config) (string, error)
	Configure(context.Context, *sql.DB, config.Config) error
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
	TableColumns(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string) (map[string]bool, error)
	TableIndexes(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string) (map[string]bool, error)
	DropIndex(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, string) error
	EnsureCompositePrimaryKey(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error
	MigrationDatabasePath(config.Config) string
	ManagedDatabaseMarkerEnabled() bool
	ColumnDefinition(string) string
	ApplicationTablesQuery(ormdialect.Renderer, string) SchemaQuery
	WorkspaceTablesQuery(ormdialect.Renderer, string) SchemaQuery
	TableExistsQuery(ormdialect.Renderer, string, string) SchemaQuery
	MigrationLedgerTypes() MigrationLedgerTypes
	EnsureMigrationNamespace(context.Context, SchemaDatabase, ormdialect.Renderer, string) error
	ConfigureMigrationTransaction(context.Context, *sql.Tx, ormdialect.Renderer, string, time.Duration, time.Duration) error
	AcquireMigrationLock(context.Context, *sql.DB, ormdialect.Renderer, MigrationLockOptions) (MigrationLock, error)
	MigrationBackupPolicy() MigrationBackupPolicy
	MigrationRollbackPolicy() MigrationRollbackPolicy
	DatabaseSchema(config.Config) string
	RendererSchema(string) string
}

// Engine is the complete database-engine strategy selected once at assembly.
// Persistence code receives this object directly and never resolves a second
// profile from a dialect at call time.
type Engine interface {
	Dialect
	EngineProfile
}

type MigrationProfile interface {
	MigrationDatabasePath(config.Config) string
	MigrationLedgerTypes() MigrationLedgerTypes
	EnsureMigrationNamespace(context.Context, SchemaDatabase, ormdialect.Renderer, string) error
	ConfigureMigrationTransaction(context.Context, *sql.Tx, ormdialect.Renderer, string, time.Duration, time.Duration) error
	AcquireMigrationLock(context.Context, *sql.DB, ormdialect.Renderer, MigrationLockOptions) (MigrationLock, error)
	MigrationBackupPolicy() MigrationBackupPolicy
	MigrationRollbackPolicy() MigrationRollbackPolicy
}

type PrimaryKeyProfile interface {
	EnsureCompositePrimaryKey(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error
}

type SchemaProfile interface {
	ManagedDatabaseMarkerEnabled() bool
	RendererSchema(string) string
	ColumnDefinition(string) string
	ApplicationTablesQuery(ormdialect.Renderer, string) SchemaQuery
	WorkspaceTablesQuery(ormdialect.Renderer, string) SchemaQuery
	TableExistsQuery(ormdialect.Renderer, string, string) SchemaQuery
	CreateIndexIfMissing(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, string, bool, ...string) error
	NormalizeAuditCursorColumns(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error
	TableColumns(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string) (map[string]bool, error)
	TableIndexes(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string) (map[string]bool, error)
	DropIndex(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, string) error
}

type SchemaTypes struct {
	Boolean         string
	FalseLiteral    string
	DefaultText     string
	DocumentText    string
	IndexedText     string
	AuditCursorText string
}

type SchemaQuery struct {
	Statement string
	Arguments []any
}

type MigrationLedgerTypes struct {
	Key       string
	Timestamp string
}

type MigrationLockOptions struct {
	DatabasePath   string
	DatabaseSchema string
	Owner          string
	LockTimeout    time.Duration
	ConnectTimeout time.Duration
}

type MigrationLock struct {
	Connection *sql.Conn
	Release    func()
}

type MigrationBackupPolicy struct {
	LocalSnapshot    bool
	ExternalEvidence bool
	EvidenceEngine   string
	BackupIDPrefix   string
}

type MigrationRollbackPolicy struct {
	Mode                   string
	RequiresVerifiedBackup bool
	Procedure              []string
}

type SchemaDatabase interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}
