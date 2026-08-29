// Package base owns the database/sql handle and portable SQL rendering shared
// by Identity persistence adapters. Database-specific behavior is supplied by
// an engine profile; business repositories do not inspect driver names.
package base

import (
	"database/sql"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type SQLDatabase struct {
	DB             *sql.DB
	SQLRenderer    ormdialect.Renderer
	DatabaseSchema string
	RelationPrefix string
	Engine         driver.Engine
}

func NewSQLDatabase(database *sql.DB, engine driver.Engine, schema, relationPrefix string) *SQLDatabase {
	schema, relationPrefix = strings.TrimSpace(schema), strings.TrimSpace(relationPrefix)
	var renderer ormdialect.Renderer
	if relationPrefix != "" {
		renderer, _ = engine.SQLDialect().WithNamespace(schema, relationPrefix)
	} else {
		renderer = engine.SQLDialect().WithSchema(schema)
	}
	return &SQLDatabase{
		DB: database, SQLRenderer: renderer, DatabaseSchema: schema,
		RelationPrefix: relationPrefix, Engine: engine,
	}
}
