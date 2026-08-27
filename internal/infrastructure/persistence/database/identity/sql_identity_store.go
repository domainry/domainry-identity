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
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite"
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
	memory            *MemoryIdentityStore
	roleRequestsReady atomic.Bool
}

var _ identityrepository.IdentityRepository = (*SQLIdentityStore)(nil)
var _ identityrepository.IdentityWorkforceRepository = (*SQLIdentityStore)(nil)

func (s *SQLIdentityStore) identifier(value string) string {
	if s.driver == "mysql" {
		return mysql.Dialect{}.Identifier(value)
	}
	return sqlite.Dialect{}.Identifier(value)
}

func (s *SQLIdentityStore) tableIdentifier(value string) string {
	if s.driver == "postgres" && strings.TrimSpace(s.schema) != "" {
		return sqlite.Dialect{}.Identifier(s.schema) + "." + sqlite.Dialect{}.Identifier(value)
	}
	return s.identifier(value)
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
	store := &SQLIdentityStore{db: db, schemaDB: schemaDB, driver: driver, schema: databaseSchema, memory: NewMemoryIdentityStore()}
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
