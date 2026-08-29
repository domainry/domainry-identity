package driver

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

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
	TableColumns(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string) (map[string]bool, error)
	TableIndexes(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string) (map[string]bool, error)
	DropIndex(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, string) error
	EnsureCompositePrimaryKey(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error
	MigrationDatabasePath(config.Config) string
	ManagedDatabaseMarkerEnabled() bool
	ColumnDefinition(string) string
	ApplicationTablesQuery(ormdialect.Renderer, string) SchemaQuery
	WorkspaceTablesQuery(ormdialect.Renderer, string) SchemaQuery
	MigrationLedgerTypes() MigrationLedgerTypes
	EnsureMigrationNamespace(context.Context, SchemaDatabase, ormdialect.Renderer, string) error
	ConfigureMigrationTransaction(context.Context, *sql.Tx, ormdialect.Renderer, string, time.Duration, time.Duration) error
	AcquireMigrationLock(context.Context, *sql.DB, ormdialect.Renderer, MigrationLockOptions) (MigrationLock, error)
	MigrationBackupPolicy() MigrationBackupPolicy
	MigrationRollbackPolicy() MigrationRollbackPolicy
	DatabaseSchema(config.Config) string
	RendererSchema(string) string
	WorkspaceRLSSupported() bool
	ApplyWorkspaceRLS(context.Context, *sql.DB, ormdialect.Renderer, string, string, string) error
	InspectWorkspaceRLS(context.Context, *sql.DB, ormdialect.Renderer, string, string, string) (WorkspaceRLSStatus, error)
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
	LocalSnapshot  bool
	EvidenceEngine string
	BackupIDPrefix string
}

type MigrationRollbackPolicy struct {
	Mode                   string
	RequiresVerifiedBackup bool
	Procedure              []string
}

type WorkspaceRLSStatus struct {
	Enabled         bool     `json:"enabled"`
	Forced          bool     `json:"forced"`
	ApplicationRole string   `json:"application_role,omitempty"`
	RoleOwnsTable   bool     `json:"role_owns_table"`
	RoleBypassRLS   bool     `json:"role_bypass_rls"`
	PolicyVersion   string   `json:"policy_version,omitempty"`
	CoveredTables   []string `json:"covered_tables,omitempty"`
	MissingTables   []string `json:"missing_tables,omitempty"`
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
func (portableEngineProfile) TableColumns(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string) (map[string]bool, error) {
	return nil, fmt.Errorf("database engine does not support column introspection")
}
func (portableEngineProfile) TableIndexes(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string) (map[string]bool, error) {
	return nil, fmt.Errorf("database engine does not support index introspection")
}
func (portableEngineProfile) DropIndex(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, string) error {
	return fmt.Errorf("database engine does not support index deletion")
}
func (portableEngineProfile) EnsureCompositePrimaryKey(context.Context, SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error {
	return fmt.Errorf("database engine does not support composite primary-key migration")
}
func (portableEngineProfile) MigrationDatabasePath(config.Config) string { return "" }
func (portableEngineProfile) ManagedDatabaseMarkerEnabled() bool         { return true }
func (portableEngineProfile) ColumnDefinition(definition string) string {
	return strings.TrimSpace(definition)
}
func (portableEngineProfile) ApplicationTablesQuery(ormdialect.Renderer, string) SchemaQuery {
	return SchemaQuery{}
}
func (portableEngineProfile) WorkspaceTablesQuery(ormdialect.Renderer, string) SchemaQuery {
	return SchemaQuery{}
}
func (portableEngineProfile) MigrationLedgerTypes() MigrationLedgerTypes {
	return MigrationLedgerTypes{Key: "TEXT", Timestamp: "TEXT"}
}
func (portableEngineProfile) EnsureMigrationNamespace(context.Context, SchemaDatabase, ormdialect.Renderer, string) error {
	return nil
}
func (portableEngineProfile) ConfigureMigrationTransaction(context.Context, *sql.Tx, ormdialect.Renderer, string, time.Duration, time.Duration) error {
	return nil
}
func (portableEngineProfile) AcquireMigrationLock(context.Context, *sql.DB, ormdialect.Renderer, MigrationLockOptions) (MigrationLock, error) {
	return MigrationLock{}, fmt.Errorf("database engine does not support migration locking")
}
func (portableEngineProfile) MigrationBackupPolicy() MigrationBackupPolicy {
	return MigrationBackupPolicy{}
}
func (portableEngineProfile) MigrationRollbackPolicy() MigrationRollbackPolicy {
	return MigrationRollbackPolicy{Mode: "unsupported", RequiresVerifiedBackup: true}
}
func (portableEngineProfile) DatabaseSchema(config.Config) string { return "" }
func (portableEngineProfile) RendererSchema(string) string        { return "" }
func (portableEngineProfile) WorkspaceRLSSupported() bool         { return false }
func (portableEngineProfile) ApplyWorkspaceRLS(context.Context, *sql.DB, ormdialect.Renderer, string, string, string) error {
	return nil
}
func (portableEngineProfile) InspectWorkspaceRLS(context.Context, *sql.DB, ormdialect.Renderer, string, string, string) (WorkspaceRLSStatus, error) {
	return WorkspaceRLSStatus{}, nil
}

type engineProfileProvider interface{ EngineProfile() EngineProfile }

func ProfileFor(value Dialect) EngineProfile {
	if provider, ok := value.(engineProfileProvider); ok {
		return provider.EngineProfile()
	}
	if profile, ok := value.(EngineProfile); ok {
		return profile
	}
	return portableEngineProfile{}
}
