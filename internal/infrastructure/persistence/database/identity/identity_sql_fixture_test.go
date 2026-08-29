package identity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite"
)

func scriptedSQLIdentity(state *identitySQLState) (*SQLIdentityStore, func()) {
	db := sql.OpenDB(identitySQLConnector{state: state})
	engine := sqlite.NewEngine()
	return &SQLIdentityStore{db: db, renderer: engine.SQLDialect().WithSchema(""), engine: engine, memory: NewMemoryIdentityStore()}, func() { _ = db.Close() }
}

type identitySQLState struct {
	execCount, execFailAt        int
	rowsFailAt                   int
	rowsZeroAt                   int
	queryCount, queryFailAt      int
	failure, beginErr, commitErr error
	querySteps                   []identitySQLQueryStep
}
type identitySQLQueryStep struct {
	columns []string
	rows    [][]driver.Value
	nextErr error
}
type identitySQLConnector struct{ state *identitySQLState }

func (c identitySQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &identitySQLConn{state: c.state}, nil
}
func (identitySQLConnector) Driver() driver.Driver { return identitySQLDriver{} }

type identitySQLDriver struct{}

func (identitySQLDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type identitySQLConn struct{ state *identitySQLState }

func (*identitySQLConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (*identitySQLConn) Close() error                        { return nil }
func (c *identitySQLConn) Begin() (driver.Tx, error) {
	if c.state.beginErr != nil {
		return nil, c.state.beginErr
	}
	return identitySQLTx{state: c.state}, nil
}
func (c *identitySQLConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}
func (c *identitySQLConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.state.execCount++
	if c.state.execCount == c.state.execFailAt {
		return nil, c.state.failure
	}
	if c.state.execCount == c.state.rowsFailAt {
		return identitySQLResult{err: c.state.failure}, nil
	}
	if c.state.execCount == c.state.rowsZeroAt {
		return driver.RowsAffected(0), nil
	}
	return driver.RowsAffected(1), nil
}

type identitySQLResult struct{ err error }

func (identitySQLResult) LastInsertId() (int64, error)   { return 0, nil }
func (r identitySQLResult) RowsAffected() (int64, error) { return 0, r.err }
func (c *identitySQLConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	c.state.queryCount++
	if c.state.queryCount == c.state.queryFailAt {
		return nil, c.state.failure
	}
	if len(c.state.querySteps) == 0 {
		return &identitySQLRows{}, nil
	}
	step := c.state.querySteps[0]
	c.state.querySteps = c.state.querySteps[1:]
	return &identitySQLRows{columns: step.columns, rows: step.rows, nextErr: step.nextErr}, nil
}

type identitySQLTx struct{ state *identitySQLState }

func (t identitySQLTx) Commit() error { return t.state.commitErr }
func (identitySQLTx) Rollback() error { return nil }

type identitySQLRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
	nextErr error
}

func (r *identitySQLRows) Columns() []string { return r.columns }
func (*identitySQLRows) Close() error        { return nil }
func (r *identitySQLRows) Next(values []driver.Value) error {
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
