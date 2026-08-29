package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (Dialect) ManagedDatabaseMarkerEnabled() bool        { return true }
func (Dialect) ColumnDefinition(definition string) string { return strings.TrimSpace(definition) }
func (Dialect) RendererSchema(schema string) string       { return strings.TrimSpace(schema) }
func (Dialect) ApplicationTablesQuery(renderer ormdialect.Renderer, databaseSchema string) driver.SchemaQuery {
	return driver.SchemaQuery{
		Statement: "SELECT table_name FROM information_schema.tables WHERE table_schema = " + renderer.Placeholder(1),
		Arguments: []any{databaseSchema},
	}
}
func (Dialect) WorkspaceTablesQuery(renderer ormdialect.Renderer, databaseSchema string) driver.SchemaQuery {
	return driver.SchemaQuery{
		Statement: "SELECT DISTINCT table_name FROM information_schema.columns WHERE table_schema = " + renderer.Placeholder(1) + " AND column_name = 'workspace_id' ORDER BY table_name",
		Arguments: []any{databaseSchema},
	}
}
func (Dialect) WorkspaceRLSSupported() bool { return true }
func (Dialect) ApplyWorkspaceRLS(ctx context.Context, database *sql.DB, renderer ormdialect.Renderer, databaseSchema, applicationRole, policyVersion string) error {
	tables, err := postgresWorkspaceTables(ctx, database, renderer, databaseSchema)
	if err != nil {
		return err
	}
	role := renderer.Identifier(applicationRole)
	policy := renderer.Identifier("domainry_identity_workspace_" + policyVersion)
	for _, table := range tables {
		relation := renderer.Table(table)
		statements := []string{
			"ALTER TABLE " + relation + " ENABLE ROW LEVEL SECURITY",
			"ALTER TABLE " + relation + " FORCE ROW LEVEL SECURITY",
			"DROP POLICY IF EXISTS " + policy + " ON " + relation,
			"CREATE POLICY " + policy + " ON " + relation + " FOR ALL TO " + role +
				" USING (" + renderer.Identifier("workspace_id") + "::text = NULLIF(current_setting('domainry.workspace_id', true), ''))" +
				" WITH CHECK (" + renderer.Identifier("workspace_id") + "::text = NULLIF(current_setting('domainry.workspace_id', true), ''))",
		}
		for _, statement := range statements {
			if _, err := database.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply workspace RLS policy to %s: %w", table, err)
			}
		}
	}
	const ledgerTable = "_identity_rls_policies"
	if _, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+renderer.Table(ledgerTable)+" ("+renderer.Identifier("version")+" TEXT PRIMARY KEY, "+renderer.Identifier("applied_at")+" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)"); err != nil {
		return fmt.Errorf("prepare workspace RLS policy ledger: %w", err)
	}
	statement, arguments, err := ormbuilder.NewInsertBuilder(renderer, ledgerTable).Columns("version").Values(policyVersion).OnConflictDoNothing("version").Build()
	if err != nil {
		return fmt.Errorf("build workspace RLS policy ledger insert: %w", err)
	}
	if _, err := database.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("record workspace RLS policy version: %w", err)
	}
	return nil
}

func (Dialect) InspectWorkspaceRLS(ctx context.Context, database *sql.DB, renderer ormdialect.Renderer, databaseSchema, applicationRole, policyVersion string) (driver.WorkspaceRLSStatus, error) {
	tables, err := postgresWorkspaceTables(ctx, database, renderer, databaseSchema)
	if err != nil {
		return driver.WorkspaceRLSStatus{}, err
	}
	status := driver.WorkspaceRLSStatus{Enabled: true, Forced: true, ApplicationRole: applicationRole, PolicyVersion: policyVersion}
	policyName := "domainry_identity_workspace_" + policyVersion
	for _, table := range tables {
		var enabled, forced, roleOwnsTable, roleBypassRLS, policyExists bool
		err := database.QueryRowContext(ctx, `SELECT c.relrowsecurity, c.relforcerowsecurity,
c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user),
COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user), true),
EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = $1 AND tablename = $2 AND policyname = $3 AND (current_user = ANY(roles) OR 'public' = ANY(roles)))
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2`, databaseSchema, table, policyName).Scan(&enabled, &forced, &roleOwnsTable, &roleBypassRLS, &policyExists)
		if err != nil {
			return driver.WorkspaceRLSStatus{}, fmt.Errorf("inspect workspace RLS policy for %s: %w", table, err)
		}
		status.Forced = status.Forced && forced
		status.RoleOwnsTable = status.RoleOwnsTable || roleOwnsTable
		status.RoleBypassRLS = status.RoleBypassRLS || roleBypassRLS
		if enabled && forced && !roleOwnsTable && !roleBypassRLS && policyExists {
			status.CoveredTables = append(status.CoveredTables, table)
		} else {
			status.MissingTables = append(status.MissingTables, table)
		}
	}
	var versionCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+renderer.Table("_identity_rls_policies")+" WHERE "+renderer.Identifier("version")+" = "+renderer.Placeholder(1), policyVersion).Scan(&versionCount); err != nil {
		return driver.WorkspaceRLSStatus{}, fmt.Errorf("verify workspace RLS policy version %s: %w", policyVersion, err)
	}
	if versionCount != 1 {
		return driver.WorkspaceRLSStatus{}, fmt.Errorf("verify workspace RLS policy version %s: missing ledger entry", policyVersion)
	}
	return status, nil
}

func postgresWorkspaceTables(ctx context.Context, database *sql.DB, renderer ormdialect.Renderer, databaseSchema string) ([]string, error) {
	rows, err := database.QueryContext(ctx, "SELECT DISTINCT table_name FROM information_schema.columns WHERE table_schema = "+renderer.Placeholder(1)+" AND column_name = 'workspace_id' ORDER BY table_name", databaseSchema)
	if err != nil {
		return nil, fmt.Errorf("inventory workspace RLS tables: %w", err)
	}
	defer rows.Close()
	tables := []string{}
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(tables)
	return tables, nil
}

func SetLocalWorkspaceRLSContext(ctx context.Context, transaction *sql.Tx, renderer ormdialect.Renderer, workspaceID, actorID string) error {
	if transaction == nil {
		return fmt.Errorf("workspace RLS transaction is required")
	}
	if strings.TrimSpace(workspaceID) == "" {
		return fmt.Errorf("workspace RLS context requires workspace_id")
	}
	if _, err := transaction.ExecContext(ctx, "SELECT set_config('domainry.workspace_id', "+renderer.Placeholder(1)+", true), set_config('domainry.actor_id', "+renderer.Placeholder(2)+", true)", workspaceID, actorID); err != nil {
		return fmt.Errorf("set transaction-local workspace RLS context: %w", err)
	}
	return nil
}

func (Dialect) CreateIndexIfMissing(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, databaseSchema, relationPrefix, table, index string, unique bool, columns ...string) error {
	indexes, err := (Dialect{}).TableIndexes(ctx, database, renderer, databaseSchema, relationPrefix, table)
	if err != nil || indexes[index] {
		return err
	}
	prefix := "CREATE INDEX IF NOT EXISTS "
	if unique {
		prefix = "CREATE UNIQUE INDEX IF NOT EXISTS "
	}
	if _, err := database.ExecContext(ctx, prefix+renderer.Identifier(index)+" ON "+renderer.Table(table)+" ("+postgresSchemaColumnList(renderer, columns)+")"); err != nil {
		return fmt.Errorf("create PostgreSQL index %s: %w", index, err)
	}
	return nil
}

func (Dialect) TableColumns(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, databaseSchema, relationPrefix, table string) (map[string]bool, error) {
	query := "SELECT column_name FROM information_schema.columns WHERE table_schema = " + renderer.Placeholder(1) + " AND table_name = " + renderer.Placeholder(2)
	rows, err := database.QueryContext(ctx, query, databaseSchema, relationPrefix+table)
	if err != nil {
		return nil, err
	}
	return postgresNames(rows, "column")
}

func (Dialect) TableIndexes(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, databaseSchema, relationPrefix, table string) (map[string]bool, error) {
	query := "SELECT indexname FROM pg_indexes WHERE schemaname = " + renderer.Placeholder(1) + " AND tablename = " + renderer.Placeholder(2)
	rows, err := database.QueryContext(ctx, query, databaseSchema, relationPrefix+table)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL indexes for %s: %w", table, err)
	}
	return postgresNames(rows, "index")
}

func (Dialect) DropIndex(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _, _, _, index string) error {
	_, err := database.ExecContext(ctx, "DROP INDEX IF EXISTS "+renderer.Identifier(index))
	return err
}

func (Dialect) NormalizeAuditCursorColumns(context.Context, driver.SchemaDatabase, ormdialect.Renderer, string, string, string, ...string) error {
	return nil
}

func postgresNames(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}, kind string) (map[string]bool, error) {
	defer rows.Close()
	values := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan PostgreSQL %s: %w", kind, err)
		}
		values[name] = true
	}
	return values, rows.Err()
}

func postgresSchemaColumnList(renderer ormdialect.Renderer, columns []string) string {
	quoted := make([]string, len(columns))
	for index, column := range columns {
		quoted[index] = renderer.Identifier(column)
	}
	return strings.Join(quoted, ", ")
}
