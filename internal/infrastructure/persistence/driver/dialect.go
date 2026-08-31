package driver

import (
	"context"
	"database/sql"
	"time"

	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

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
	ApplyUpdateLock(*query.SelectBuilder) *query.SelectBuilder
	ApplyUpsert(*query.InsertBuilder, []string, ...string) *query.InsertBuilder
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
