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

func dialectFor(driver string) (dialect, error) {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "", "sqlite", "sqlite3":
		return sqlite.Dialect{}, nil
	case "mysql":
		return mysql.Dialect{}, nil
	case "postgres", "postgresql", "pgx":
		return postgres.Dialect{}, nil
	default:
		return nil, fmt.Errorf("unsupported database driver %q", driver)
	}
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
