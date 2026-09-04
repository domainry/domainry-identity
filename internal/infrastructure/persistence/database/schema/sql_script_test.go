package schema

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"

	persistencedriver "github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	mysqlpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql"
	postgrespersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	sqlitepersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

var errSchemaSQL = errors.New("scripted schema SQL failure")

const mysqlIndexedTextType = "VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin"

type schemaSQLState struct {
	execSteps   []schemaSQLExecStep
	execQueries []string
	querySteps  []schemaSQLQueryStep
	beginErr    error
	commitErr   error
}

type schemaSQLExecStep struct{ err error }
type schemaSQLQueryStep struct {
	columns      []string
	rows         [][]driver.Value
	err, nextErr error
}

func openSchemaScriptedDB(state *schemaSQLState) *sql.DB {
	return sql.OpenDB(schemaSQLConnector{state})
}

func schemaStoreForState(state *schemaSQLState, dialect ...string) (scriptedSchemaStore, func()) {
	database := openSchemaScriptedDB(state)
	store := scriptedSchemaStore{db: database}
	if len(dialect) > 0 {
		store.driver = dialect[0]
	}
	return store, func() { _ = database.Close() }
}

type schemaSQLConnector struct{ state *schemaSQLState }

func (c schemaSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &schemaSQLConn{c.state}, nil
}
func (schemaSQLConnector) Driver() driver.Driver { return schemaSQLDriver{} }

type schemaSQLDriver struct{}

func (schemaSQLDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("use schema connector")
}

type schemaSQLConn struct{ state *schemaSQLState }

func (*schemaSQLConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (*schemaSQLConn) Close() error                        { return nil }
func (c *schemaSQLConn) Begin() (driver.Tx, error) {
	if c.state.beginErr != nil {
		return nil, c.state.beginErr
	}
	return schemaSQLTx{state: c.state}, nil
}
func (c *schemaSQLConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}
func (c *schemaSQLConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.state.execQueries = append(c.state.execQueries, query)
	step := schemaSQLExecStep{}
	if len(c.state.execSteps) > 0 {
		step, c.state.execSteps = c.state.execSteps[0], c.state.execSteps[1:]
	}
	if step.err != nil {
		return nil, step.err
	}
	return driver.RowsAffected(1), nil
}
func (c *schemaSQLConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	step := schemaSQLQueryStep{}
	if len(c.state.querySteps) > 0 {
		step, c.state.querySteps = c.state.querySteps[0], c.state.querySteps[1:]
	}
	if step.err != nil {
		return nil, step.err
	}
	return &schemaSQLRows{columns: step.columns, rows: step.rows, nextErr: step.nextErr}, nil
}

type schemaSQLTx struct{ state *schemaSQLState }

func (t schemaSQLTx) Commit() error { return t.state.commitErr }
func (schemaSQLTx) Rollback() error { return nil }

type schemaSQLRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
	nextErr error
}

func (r *schemaSQLRows) Columns() []string { return r.columns }
func (*schemaSQLRows) Close() error        { return nil }
func (r *schemaSQLRows) Next(values []driver.Value) error {
	if r.index < len(r.rows) {
		copy(values, r.rows[r.index])
		r.index++
		return nil
	}
	if r.nextErr != nil {
		err := r.nextErr
		r.nextErr = nil
		return err
	}
	return io.EOF
}

type scriptedSchemaStore struct {
	db     *sql.DB
	driver string
}

func (s scriptedSchemaStore) SchemaDB() SQLDatabase               { return s.db }
func (s scriptedSchemaStore) SchemaRenderer() ormdialect.Renderer { return s.renderer() }
func (s scriptedSchemaStore) MaxParameters() int                  { return 999 }
func (s scriptedSchemaStore) Driver() string {
	if s.driver != "" {
		return s.driver
	}
	return "sqlite"
}
func (scriptedSchemaStore) DatabaseSchema() string              { return "main" }
func (scriptedSchemaStore) Identifier(value string) string      { return `"` + value + `"` }
func (scriptedSchemaStore) TableIdentifier(value string) string { return `"` + value + `"` }
func (scriptedSchemaStore) Placeholder(int) string              { return "?" }
func (s scriptedSchemaStore) SchemaTableExists(ctx context.Context, table string) (bool, error) {
	query := s.engineProfile().TableExistsQuery(s.renderer(), s.DatabaseSchema(), table)
	var count int
	err := s.db.QueryRowContext(ctx, query.Statement, query.Arguments...).Scan(&count)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return count > 0, err
}
func (scriptedSchemaStore) CreateIndexIfMissing(context.Context, string, string, bool, ...string) error {
	return nil
}
func (scriptedSchemaStore) NormalizeAuditCursorColumns(context.Context, string, ...string) error {
	return nil
}
func (s scriptedSchemaStore) TableColumns(ctx context.Context, table string) (map[string]bool, error) {
	return s.engineProfile().TableColumns(ctx, s.db, s.renderer(), s.DatabaseSchema(), "", table)
}
func (s scriptedSchemaStore) TableIndexes(ctx context.Context, table string) (map[string]bool, error) {
	return s.engineProfile().TableIndexes(ctx, s.db, s.renderer(), s.DatabaseSchema(), "", table)
}
func (s scriptedSchemaStore) DropIndex(ctx context.Context, table, index string) error {
	return s.engineProfile().DropIndex(ctx, s.db, s.renderer(), s.DatabaseSchema(), "", table, index)
}
func (scriptedSchemaStore) EnsureCompositePrimaryKey(context.Context, string, ...string) error {
	return nil
}
func (scriptedSchemaStore) MetadataIDColumnType() string       { return "TEXT" }
func (scriptedSchemaStore) LocalizedTextKeyColumnType() string { return "TEXT" }
func (s scriptedSchemaStore) SchemaTypes() persistencedriver.SchemaTypes {
	if s.Driver() == "mysql" {
		return persistencedriver.SchemaTypes{Boolean: "BOOLEAN", FalseLiteral: "0", DefaultText: "VARCHAR(255)", DocumentText: "LONGTEXT", IndexedText: mysqlIndexedTextType, AuditCursorText: mysqlIndexedTextType}
	}
	return persistencedriver.SchemaTypes{Boolean: "INTEGER", FalseLiteral: "0", DefaultText: "TEXT", DocumentText: "TEXT", IndexedText: "TEXT", AuditCursorText: "TEXT"}
}
func (scriptedSchemaStore) ColumnDefinition(value string) string { return value }

func (s scriptedSchemaStore) engineProfile() persistencedriver.EngineProfile {
	switch s.Driver() {
	case "mysql":
		return mysqlpersistence.NewEngine()
	case "postgres":
		return postgrespersistence.NewEngine()
	default:
		return sqlitepersistence.NewEngine()
	}
}

func (s scriptedSchemaStore) renderer() ormdialect.Renderer {
	dialect, _ := ormdialect.Parse(s.Driver())
	renderer, _ := dialect.WithNamespace(func() string {
		if s.Driver() == "postgres" {
			return s.DatabaseSchema()
		}
		return ""
	}(), "")
	return renderer
}
