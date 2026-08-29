package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	_ "modernc.org/sqlite"
)

type Dialect struct{}

func (Dialect) Name() string { return "sqlite" }

func (Dialect) SQLDriver() string { return "sqlite" }

func (Dialect) DSN(cfg config.Config) (string, error) {
	if strings.TrimSpace(cfg.DatabaseDSN) != "" {
		return strings.TrimSpace(cfg.DatabaseDSN), nil
	}
	if strings.TrimSpace(cfg.DBPath) == "" {
		return "data/app.db", nil
	}
	return strings.TrimSpace(cfg.DBPath), nil
}

func (Dialect) Configure(ctx context.Context, db *sql.DB, dsn string) error {
	if dsn != ":memory:" && !strings.HasPrefix(dsn, "file:") {
		if err := os.MkdirAll(filepath.Dir(dsn), 0o755); err != nil {
			return fmt.Errorf("create sqlite database directory: %w", err)
		}
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		return fmt.Errorf("configure sqlite busy timeout: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("configure sqlite database: %w", err)
	}
	return nil
}

func (Dialect) Identifier(value string) string {
	return ormdialect.QuoteIdentifier(value, `"`)
}

func (Dialect) Placeholder(position int) string {
	return ormdialect.QuestionPlaceholder(position)
}

func (Dialect) SchemaMigrationSQL() string {
	return `CREATE TABLE IF NOT EXISTS "_schema_migrations" ("path" TEXT PRIMARY KEY, "applied_at" TEXT NOT NULL)`
}
