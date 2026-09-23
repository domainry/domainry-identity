// SQL identity persistence.
package identity

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	persistencedriver "github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

// identityReadExecutor is the read-only SQL contract shared by the pooled
// database handle and the Runtime Action transaction executor.
type identityReadExecutor interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// reader returns the Runtime Action transaction executor when the caller runs
// inside an Action execution, so identity reads reuse the transaction
// connection instead of blocking on the (possibly single-connection) pool.
func (s *SQLIdentityStore) reader(ctx context.Context) identityReadExecutor {
	if tx := transaction.ExecutorFromContext(ctx); tx != nil {
		return tx
	}
	return s.db
}

type SQLIdentityStore struct {
	db                          *sql.DB
	schemaDB                    identityschema.SQLDatabase
	engine                      persistencedriver.EngineProfile
	renderer                    ormdialect.Renderer
	memory                      *MemoryIdentityStore
	subjectLifecyclePersistence atomic.Bool
	operationsPersistence       atomic.Bool
}

var _ identityrepository.IdentityRepository = (*SQLIdentityStore)(nil)

// BindSubjectLifecyclePersistence enables the owner-side subject lifecycle
// path only after the host has installed the shared Lifecycle tables.
func (s *SQLIdentityStore) BindSubjectLifecyclePersistence() {
	if s != nil {
		s.subjectLifecyclePersistence.Store(true)
	}
}

func (s *SQLIdentityStore) SubjectLifecyclePersistenceBound() bool {
	return s != nil && s.subjectLifecyclePersistence.Load()
}

func (s *SQLIdentityStore) BindOperationsPersistence() {
	if s != nil {
		s.operationsPersistence.Store(true)
	}
}

func (s *SQLIdentityStore) OperationsPersistenceBound() bool {
	return s != nil && s.operationsPersistence.Load()
}

func (s *SQLIdentityStore) sqlRenderer() ormdialect.Renderer {
	return s.renderer
}

func (s *SQLIdentityStore) engineProfile() persistencedriver.EngineProfile {
	if s.engine != nil {
		return s.engine
	}
	panic("identity SQL store requires an engine profile")
}

func NewSQLIdentityStore(ctx context.Context, db *sql.DB, engine persistencedriver.Engine, schema ...string) (*SQLIdentityStore, error) {
	return NewSQLIdentityStoreWithSchema(ctx, db, db, engine, schema...)
}

func NewSQLIdentityStoreWithSchema(ctx context.Context, db *sql.DB, schemaDB identityschema.SQLDatabase, engine persistencedriver.Engine, schema ...string) (*SQLIdentityStore, error) {
	databaseSchema := ""
	if len(schema) > 0 {
		databaseSchema = strings.TrimSpace(schema[0])
	}
	relationPrefix := ""
	if len(schema) > 1 {
		relationPrefix = strings.TrimSpace(schema[1])
	}
	if engine == nil {
		return nil, fmt.Errorf("identity SQL store requires a database engine")
	}
	renderer, err := engine.SQLDialect().WithNamespace(engine.RendererSchema(databaseSchema), relationPrefix)
	if err != nil {
		return nil, err
	}
	store := &SQLIdentityStore{db: db, schemaDB: schemaDB, engine: engine, renderer: renderer, memory: NewMemoryIdentityStore()}
	return store, nil
}

func identityWorkspaceID(value string) (string, error) {
	workspace, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return workspace.String(), nil
}
