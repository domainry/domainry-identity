// SQL identity persistence.
package identity

import (
	"context"
	"database/sql"
	"strings"
	"sync/atomic"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

// identityReadExecutor is the read-only SQL surface shared by the pooled
// database handle and the Runtime Action transaction executor.
type identityReadExecutor interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// reader returns the Runtime Action transaction executor when the caller runs
// inside an Action execution, so identity reads reuse the transaction
// connection instead of blocking on the (possibly single-connection) pool.
func (s *SQLIdentityStore) reader(ctx context.Context) identityReadExecutor {
	if tx := database.ActionExecutionTransaction(ctx); tx != nil {
		return tx
	}
	return s.db
}

type SQLIdentityStore struct {
	db                *sql.DB
	schemaDB          identityschema.SQLDatabase
	driver            string
	schema            string
	relationPrefix    string
	renderer          *ormdialect.Renderer
	rendererConfig    string
	memory            *MemoryIdentityStore
	roleRequestsReady atomic.Bool
}

var _ identityrepository.IdentityRepository = (*SQLIdentityStore)(nil)
var _ identityrepository.IdentityWorkforceRepository = (*SQLIdentityStore)(nil)

func (s *SQLIdentityStore) identifier(value string) string {
	return s.sqlRenderer().Identifier(value)
}

func (s *SQLIdentityStore) sqlDialect() ormdialect.Dialect {
	value, err := ormdialect.Parse(s.driver)
	if err != nil {
		panic(err)
	}
	return value
}

func (s *SQLIdentityStore) tableIdentifier(value string) string {
	return s.sqlRenderer().Table(value)
}

func (s *SQLIdentityStore) sqlRenderer() ormdialect.Renderer {
	configuration := strings.Join([]string{s.driver, strings.TrimSpace(s.schema), strings.TrimSpace(s.relationPrefix)}, "\x00")
	if s.renderer != nil && s.rendererConfig == configuration {
		return *s.renderer
	}
	dialect, err := ormdialect.Parse(s.driver)
	if err != nil {
		panic(err)
	}
	schema := ""
	if dialect.Name() == ormdialect.Postgres {
		schema = s.schema
	}
	value, err := dialect.WithNamespace(schema, s.relationPrefix)
	if err != nil {
		panic(err)
	}
	s.renderer = &value
	s.rendererConfig = configuration
	return value
}

func (s *SQLIdentityStore) identityColumns(values ...string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, s.identifier(value))
	}
	return strings.Join(quoted, ", ")
}

func NewSQLIdentityStore(ctx context.Context, db *sql.DB, driver string, schema ...string) (*SQLIdentityStore, error) {
	return NewSQLIdentityStoreWithSchema(ctx, db, db, driver, schema...)
}

func NewSQLIdentityStoreWithSchema(ctx context.Context, db *sql.DB, schemaDB identityschema.SQLDatabase, driver string, schema ...string) (*SQLIdentityStore, error) {
	databaseSchema := ""
	if len(schema) > 0 {
		databaseSchema = strings.TrimSpace(schema[0])
	}
	relationPrefix := ""
	if len(schema) > 1 {
		relationPrefix = strings.TrimSpace(schema[1])
	}
	dialect, err := ormdialect.Parse(driver)
	if err != nil {
		return nil, err
	}
	rendererSchema := ""
	if dialect.Name() == ormdialect.Postgres {
		rendererSchema = databaseSchema
	}
	renderer, err := dialect.WithNamespace(rendererSchema, relationPrefix)
	if err != nil {
		return nil, err
	}
	configuration := strings.Join([]string{driver, databaseSchema, relationPrefix}, "\x00")
	store := &SQLIdentityStore{db: db, schemaDB: schemaDB, driver: driver, schema: databaseSchema, relationPrefix: relationPrefix, renderer: &renderer, rendererConfig: configuration, memory: NewMemoryIdentityStore()}
	if err := store.ensureRoleRequestsTable(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func identityWorkspaceID(value string) (string, error) {
	workspace, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return workspace.String(), nil
}
