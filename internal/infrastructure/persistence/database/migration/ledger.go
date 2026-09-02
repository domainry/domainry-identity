package migration

import (
	"context"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Ledger struct {
	database       driver.SchemaDatabase
	engine         driver.Engine
	renderer       ormdialect.Renderer
	databaseSchema string
}

func NewLedger(database driver.SchemaDatabase, engine driver.Engine, renderer ormdialect.Renderer, databaseSchema string) *Ledger {
	return &Ledger{database: database, engine: engine, renderer: renderer, databaseSchema: databaseSchema}
}

func (ledger *Ledger) Columns() string {
	columns := []string{"path", "version", "name", "kind", "checksum", "dirty", "applied_at", "service_version", "duration_ms", "operator", "instance_id", "backup_id"}
	quoted := make([]string, len(columns))
	for index, column := range columns {
		quoted[index] = ledger.renderer.Identifier(column)
	}
	return strings.Join(quoted, ", ")
}

func (ledger *Ledger) SchemaSQL() string {
	// The host ledger must preserve engine-provided legacy physical types.
	// domainry-orm's schema types cannot represent those arbitrary type strings,
	// so only this DDL rendering remains in the migration adapter.
	types := ledger.engine.MigrationLedgerTypes()
	pathType, timeType := types.Key, types.Timestamp
	i, table := ledger.renderer.Identifier, ledger.renderer.Table
	return "CREATE TABLE IF NOT EXISTS " + table("_schema_migrations") + " (" + i("path") + " " + pathType + " PRIMARY KEY, " + i("version") + " " + pathType + " NOT NULL DEFAULT '', " + i("name") + " " + pathType + " NOT NULL DEFAULT '', " + i("kind") + " " + pathType + " NOT NULL DEFAULT 'schema', " + i("checksum") + " " + pathType + " NOT NULL DEFAULT '', " + i("dirty") + " BOOLEAN NOT NULL DEFAULT FALSE, " + i("applied_at") + " " + timeType + " NOT NULL, " + i("service_version") + " " + pathType + " NOT NULL DEFAULT '', " + i("duration_ms") + " BIGINT NOT NULL DEFAULT 0, " + i("operator") + " " + pathType + " NOT NULL DEFAULT '', " + i("instance_id") + " " + pathType + " NOT NULL DEFAULT '', " + i("backup_id") + " " + pathType + " NOT NULL DEFAULT '')"
}

func (ledger *Ledger) Ensure(ctx context.Context) error {
	if err := ledger.engine.EnsureMigrationNamespace(ctx, ledger.database, ledger.renderer, ledger.databaseSchema); err != nil {
		return err
	}
	if _, err := ledger.database.ExecContext(ctx, ledger.SchemaSQL()); err != nil {
		return err
	}
	textType := ledger.engine.MigrationLedgerTypes().Key + " NOT NULL DEFAULT ''"
	columns := []struct{ name, definition string }{{"version", textType}, {"name", textType}, {"kind", textType}, {"checksum", textType}, {"dirty", "BOOLEAN NOT NULL DEFAULT FALSE"}, {"service_version", textType}, {"duration_ms", "BIGINT NOT NULL DEFAULT 0"}, {"operator", textType}, {"instance_id", textType}, {"backup_id", textType}}
	for _, column := range columns {
		statement, arguments, buildErr := query.NewSelectBuilder(ledger.renderer, "_schema_migrations").
			Columns(column.name).Where(query.AlwaysFalse()).Build()
		if buildErr != nil {
			return buildErr
		}
		rows, queryErr := ledger.database.QueryContext(ctx, statement, arguments...)
		if queryErr == nil {
			_ = rows.Close()
			continue
		}
		// The arbitrary engine-provided legacy definition above has no ORM column
		// type equivalent; keep the compatibility ALTER beside that reason.
		if _, alterErr := ledger.database.ExecContext(ctx, "ALTER TABLE "+ledger.renderer.Table("_schema_migrations")+" ADD COLUMN "+ledger.renderer.Identifier(column.name)+" "+column.definition); alterErr != nil {
			return alterErr
		}
	}
	return nil
}
