package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestSQLiteDialectContract(t *testing.T) {
	dialect := Dialect{}
	if dialect.Name() != "sqlite" || dialect.SQLDriver() != "sqlite" || dialect.SQLDialect().Identifier("runtime_table") != `"runtime_table"` || dialect.SQLDialect().Placeholder(2) != "?" || !strings.Contains(dialect.SchemaMigrationSQL(), "_schema_migrations") {
		t.Fatalf("dialect identity contract failed")
	}
	for _, test := range []struct {
		cfg  config.Config
		want string
	}{
		{cfg: config.Config{DatabaseDSN: " file:runtime.db "}, want: "file:runtime.db?_pragma=busy_timeout%285000%29&_pragma=foreign_keys%281%29"},
		{cfg: config.Config{}, want: "data/runtime.db?_pragma=busy_timeout%285000%29&_pragma=foreign_keys%281%29"},
		{cfg: config.Config{DBPath: " runtime.db "}, want: "runtime.db?_pragma=busy_timeout%285000%29&_pragma=foreign_keys%281%29"},
	} {
		got, err := dialect.DSN(test.cfg)
		if err != nil || got != test.want {
			t.Fatalf("dsn=%q err=%v want=%q", got, err, test.want)
		}
	}

	databasePath := filepath.Join(t.TempDir(), "nested", "runtime.db")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := dialect.Configure(t.Context(), db, config.Config{DBPath: databasePath}); err != nil {
		t.Fatalf("path configure=%v", err)
	}
	if _, err := os.Stat(filepath.Dir(databasePath)); err != nil {
		t.Fatalf("database directory=%v", err)
	}
}

func TestSQLiteDialectConfigureFailures(t *testing.T) {
	dialect := Dialect{}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := dialect.Configure(t.Context(), db, config.Config{DBPath: filepath.Join(blocker, "runtime.db")}); err == nil || !strings.Contains(err.Error(), "create sqlite database directory") {
		t.Fatalf("directory error=%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dialect.Configure(ctx, db, config.Config{DBPath: filepath.Join(t.TempDir(), "cancelled.db")}); !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "busy timeout") {
		t.Fatalf("busy timeout error=%v", err)
	}

	foreignDB := sql.OpenDB(sqliteFailureConnector{})
	defer foreignDB.Close()
	if err := dialect.Configure(t.Context(), foreignDB, config.Config{DBPath: filepath.Join(t.TempDir(), "failure.db")}); err == nil || !strings.Contains(err.Error(), "configure sqlite foreign keys") {
		t.Fatalf("foreign key error=%v", err)
	}
}

type sqliteFailureConnector struct{}

func (sqliteFailureConnector) Connect(context.Context) (driver.Conn, error) {
	return &sqliteFailureConn{}, nil
}
func (sqliteFailureConnector) Driver() driver.Driver { return sqliteFailureDriver{} }

type sqliteFailureDriver struct{}

func (sqliteFailureDriver) Open(string) (driver.Conn, error) { return &sqliteFailureConn{}, nil }

type sqliteFailureConn struct{ calls int }

func (*sqliteFailureConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (*sqliteFailureConn) Close() error                        { return nil }
func (*sqliteFailureConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (c *sqliteFailureConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.calls++
	if c.calls == 2 {
		return nil, errors.New("foreign key pragma failed")
	}
	return driver.RowsAffected(0), nil
}
