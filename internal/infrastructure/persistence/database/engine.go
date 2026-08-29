package database

import (
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type databaseEngine = driver.Engine

var engineRegistry = map[string]func() driver.Engine{
	"":           func() driver.Engine { return sqlite.NewEngine() },
	"sqlite":     func() driver.Engine { return sqlite.NewEngine() },
	"sqlite3":    func() driver.Engine { return sqlite.NewEngine() },
	"mysql":      func() driver.Engine { return mysql.NewEngine() },
	"postgres":   func() driver.Engine { return postgres.NewEngine() },
	"postgresql": func() driver.Engine { return postgres.NewEngine() },
	"pgx":        func() driver.Engine { return postgres.NewEngine() },
}

func engineFor(driverName string) (driver.Engine, error) {
	factory, found := engineRegistry[strings.ToLower(strings.TrimSpace(driverName))]
	if !found {
		return nil, fmt.Errorf("unsupported database driver %q", driverName)
	}
	return factory(), nil
}

func validSQLIdentifier(value string) bool {
	return ormdialect.ValidIdentifier(value)
}

func SQLIdentifier(value string) string {
	dialect, _ := ormdialect.New(ormdialect.SQLite)
	return dialect.Identifier(value)
}

func (s *IdentityStore) metadataIDColumnType() string {
	return s.sqlBase().Engine.TextKeyColumnType(191)
}

// SetEngineForTesting exercises SQL generation contracts against the shared
// in-memory fixture without exposing the engine selection field.
func (s *IdentityStore) SetEngineForTesting(driver string) error {
	engine, err := engineFor(driver)
	if err != nil {
		return err
	}
	s.engine = engine
	s.SQLDatabase = nil
	return nil
}
