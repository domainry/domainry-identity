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

type dialect = driver.Dialect

var dialectRegistry = map[string]func() dialect{
	"":           func() dialect { return sqlite.Dialect{} },
	"sqlite":     func() dialect { return sqlite.Dialect{} },
	"sqlite3":    func() dialect { return sqlite.Dialect{} },
	"mysql":      func() dialect { return mysql.Dialect{} },
	"postgres":   func() dialect { return postgres.Dialect{} },
	"postgresql": func() dialect { return postgres.Dialect{} },
	"pgx":        func() dialect { return postgres.Dialect{} },
}

func dialectFor(driverName string) (dialect, error) {
	factory, found := dialectRegistry[strings.ToLower(strings.TrimSpace(driverName))]
	if !found {
		return nil, fmt.Errorf("unsupported database driver %q", driverName)
	}
	return factory(), nil
}

// EngineProfileFor resolves database capabilities at the persistence assembly
// boundary so repositories never branch on driver names.
func EngineProfileFor(driverName string) (driver.EngineProfile, error) {
	value, err := dialectFor(driverName)
	if err != nil {
		return nil, err
	}
	return driver.ProfileFor(value), nil
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

// SetDialectForTesting exercises SQL generation contracts against the shared
// in-memory fixture without exposing the dialect field.
func (s *IdentityStore) SetDialectForTesting(driver string) error {
	dialect, err := dialectFor(driver)
	if err != nil {
		return err
	}
	s.dialect = dialect
	s.SQLDatabase = nil
	return nil
}
