package database

import (
	"github.com/domainry/domainry-foundation/mutation"

	"context"
	"database/sql"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/failure"

	"strings"

	"github.com/domainry/domainry-foundation/secrets"
	migrationcontract "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func MutationConstraintError(err error, resource, identifier string, kind mutation.MutationConflictKind) error {
	return failure.ConstraintError(err, resource, identifier, kind)
}

func MutationTransactionError(err error, resource, identifier string) error {
	return failure.TransactionError(err, resource, identifier)
}

func NullableText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func BoolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (s *IdentityStore) InsertSystemRowContext(ctx context.Context, table string, columns []string, values []any) error {
	return s.insertSystemRowContext(ctx, table, columns, values)
}

func (s *IdentityStore) SecretMaterialKey() [32]byte            { return s.secretMaterialKey }
func (s *IdentityStore) SecretKeyProvider() secrets.KeyProvider { return s.secretKeyProvider }

func (s *IdentityStore) CreateIndexIfMissing(ctx context.Context, table, index string, unique bool, columns ...string) error {
	base := s.sqlBase()
	return base.Engine.CreateIndexIfMissing(ctx, s.schemaDatabase(), base.SQLRenderer, base.DatabaseSchema, base.RelationPrefix, table, index, unique, columns...)
}
func (s *IdentityStore) NormalizeAuditCursorColumns(ctx context.Context, table string, columns ...string) error {
	base := s.sqlBase()
	return base.Engine.NormalizeAuditCursorColumns(ctx, s.schemaDatabase(), base.SQLRenderer, base.DatabaseSchema, base.RelationPrefix, table, columns...)
}
func (s *IdentityStore) TableColumns(ctx context.Context, table string) (map[string]bool, error) {
	base := s.sqlBase()
	return base.Engine.TableColumns(ctx, s.schemaDatabase(), base.SQLRenderer, base.DatabaseSchema, base.RelationPrefix, table)
}
func (s *IdentityStore) TableIndexes(ctx context.Context, table string) (map[string]bool, error) {
	base := s.sqlBase()
	return base.Engine.TableIndexes(ctx, s.schemaDatabase(), base.SQLRenderer, base.DatabaseSchema, base.RelationPrefix, table)
}
func (s *IdentityStore) DropIndex(ctx context.Context, table, index string) error {
	base := s.sqlBase()
	return base.Engine.DropIndex(ctx, s.schemaDatabase(), base.SQLRenderer, base.DatabaseSchema, base.RelationPrefix, table, index)
}

func (s *IdentityStore) EnsureColumn(ctx context.Context, table, column, definition string) error {
	return s.ensureColumn(ctx, table, column, definition)
}

func (s *IdentityStore) MetadataIDColumnType() string        { return s.metadataIDColumnType() }
func (s *IdentityStore) SchemaRenderer() ormdialect.Renderer { return s.sqlBase().SQLRenderer }
func (s *IdentityStore) LocalizedTextKeyColumnType() string {
	return s.sqlBase().Engine.TextKeyColumnType(128)
}
func (s *IdentityStore) SchemaTypes() driver.SchemaTypes { return s.sqlBase().Engine.SchemaTypes() }
func (s *IdentityStore) ColumnDefinition(definition string) string {
	return s.columnDefinition(definition)
}

func ValidateExternalMigrationBackup(driverName, evidencePath string) error {
	_, err := migrationcontract.ValidateExternalBackup(driverName, evidencePath)
	return err
}

func MigrationPathsForEngine(cfg config.Config, engine driver.Engine) ([]string, error) {
	return migrationcontract.NewPathResolver(engine, nil).Paths(cfg)
}

func NonNilMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func recordMutationTxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelSerializable}
}
