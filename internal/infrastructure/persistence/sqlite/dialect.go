package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormbuilder "github.com/domainry/domainry-orm/query"
	ormsqlite "github.com/domainry/domainry-orm/sqlite"
	_ "modernc.org/sqlite"
)

type Dialect struct{}

func (Dialect) Name() string { return "sqlite" }

func (Dialect) MaxParameters() int           { return 999 }
func (Dialect) TextKeyColumnType(int) string { return "TEXT" }
func (Dialect) SchemaTypes() driver.SchemaTypes {
	return driver.SchemaTypes{Boolean: "INTEGER", FalseLiteral: "0", DefaultText: "TEXT", DocumentText: "TEXT", IndexedText: "TEXT", AuditCursorText: "TEXT"}
}
func (Dialect) ApplyUpdateLock(builder *ormbuilder.SelectBuilder) *ormbuilder.SelectBuilder {
	return builder
}
func (Dialect) ApplyUpsert(builder *ormbuilder.InsertBuilder, conflictColumns []string, updateColumns ...string) *ormbuilder.InsertBuilder {
	assignments := make([]ormbuilder.Assignment, len(updateColumns))
	for index, column := range updateColumns {
		assignments[index] = ormbuilder.AssignExpression(column, ormbuilder.InsertedValue(column))
	}
	return builder.OnConflictDoUpdate(conflictColumns, assignments...)
}

func (Dialect) SQLDriver() string                   { return "sqlite" }
func (Dialect) DatabaseSchema(config.Config) string { return "" }

func (Dialect) DSN(cfg config.Config) (string, error) {
	connection, err := identitySQLiteConnectionConfig(cfg)
	if err != nil {
		return "", err
	}
	return connection.DSN()
}

func (Dialect) Configure(ctx context.Context, db *sql.DB, cfg config.Config) error {
	connection, err := identitySQLiteConnectionConfig(cfg)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(connection.BusyTimeout)
	for {
		err = ormsqlite.InitializeOwned(ctx, db, connection)
		if err == nil || !sqliteBusy(err) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func sqliteBusy(err error) bool {
	message := strings.ToUpper(err.Error())
	return strings.Contains(message, "SQLITE_BUSY") || strings.Contains(message, "DATABASE IS LOCKED")
}

func identitySQLiteConnectionConfig(cfg config.Config) (ormsqlite.OwnedConnectionConfig, error) {
	dataSource := strings.TrimSpace(cfg.DatabaseDSN)
	if dataSource == "" {
		dataSource = strings.TrimSpace(cfg.DBPath)
	}
	if dataSource == "" {
		dataSource = "data/runtime.db"
	}
	normalized := strings.ToLower(dataSource)
	if normalized == ":memory:" || strings.Contains(normalized, "mode=memory") {
		return ormsqlite.OwnedConnectionConfig{}, fmt.Errorf("Identity SQLite requires a file database")
	}
	connection := ormsqlite.DefaultOwnedConnectionConfig(dataSource)
	if cfg.DatabaseLockTimeout > 0 {
		connection.BusyTimeout = cfg.DatabaseLockTimeout
	}
	if cfg.DatabaseMaxOpenConns > 0 {
		connection.MaxOpenConnections = cfg.DatabaseMaxOpenConns
	}
	if cfg.DatabaseMaxIdleConns > 0 {
		connection.MaxIdleConnections = cfg.DatabaseMaxIdleConns
	}
	if connection.MaxIdleConnections > connection.MaxOpenConnections {
		connection.MaxIdleConnections = connection.MaxOpenConnections
	}
	return connection, nil
}

func (Dialect) SQLDialect() ormdialect.Dialect {
	value, _ := ormdialect.New(ormdialect.SQLite)
	return value
}

func (Dialect) SchemaMigrationSQL() string {
	return `CREATE TABLE IF NOT EXISTS "_schema_migrations" ("path" TEXT PRIMARY KEY, "applied_at" TEXT NOT NULL)`
}
