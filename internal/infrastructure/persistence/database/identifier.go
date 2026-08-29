package database

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/connection"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

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
	engine, err := connection.EngineFor(driver)
	if err != nil {
		return err
	}
	s.engine = engine
	s.SQLDatabase = nil
	return nil
}
