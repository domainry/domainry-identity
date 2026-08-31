package workspace

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type scopeDatabase interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type ScopeValidator struct {
	database       scopeDatabase
	engine         driver.Engine
	renderer       ormdialect.Renderer
	databaseSchema string
	relationPrefix string
}

func NewScopeValidator(database scopeDatabase, engine driver.Engine, renderer ormdialect.Renderer, databaseSchema, relationPrefix string) *ScopeValidator {
	return &ScopeValidator{database: database, engine: engine, renderer: renderer, databaseSchema: databaseSchema, relationPrefix: relationPrefix}
}

// ValidateLegacyWorkspaceScopes inventories legacy tenant rows without
// rewriting them. Missing and legacy-default scopes block the migration with
// deterministic details; the migration path never guesses a replacement.
func (validator *ScopeValidator) ValidateLegacyWorkspaceScopes(ctx context.Context) error {
	tables, err := validator.InventoryWorkspaceTables(ctx)
	if err != nil {
		return err
	}
	findings := []string{}
	for _, table := range tables {
		workspaceColumn := validator.renderer.Identifier("workspace_id")
		query := "SELECT COALESCE(" + workspaceColumn + ", ''), COUNT(*) FROM " + validator.renderer.Table(table) +
			" WHERE " + workspaceColumn + " IS NULL OR TRIM(" + workspaceColumn + ") = ''" +
			" OR LOWER(TRIM(" + workspaceColumn + ")) = 'default'" +
			" GROUP BY " + workspaceColumn
		rows, queryErr := validator.database.QueryContext(ctx, query)
		if queryErr != nil {
			return fmt.Errorf("inspect legacy workspace values for %s: %w", table, queryErr)
		}
		findingsByClassification := make(map[string]int64)
		for rows.Next() {
			var observed string
			var count int64
			if err := rows.Scan(&observed, &count); err != nil {
				rows.Close()
				return err
			}
			classification := "missing_workspace"
			if strings.EqualFold(strings.TrimSpace(observed), "default") {
				classification = "legacy_default_workspace"
			}
			findingsByClassification[classification] += count
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()
		classifications := make([]string, 0, len(findingsByClassification))
		for classification := range findingsByClassification {
			classifications = append(classifications, classification)
		}
		sort.Strings(classifications)
		for _, classification := range classifications {
			findings = append(findings, fmt.Sprintf("table=%s classification=%s row_count=%d", table, classification, findingsByClassification[classification]))
		}
	}
	if len(findings) > 0 {
		return fmt.Errorf("workspace scope migration blocked: manual source-data adjudication required: %s", strings.Join(findings, "; "))
	}
	return nil
}

func (validator *ScopeValidator) InventoryWorkspaceTables(ctx context.Context) ([]string, error) {
	query := validator.engine.WorkspaceTablesQuery(validator.renderer, validator.databaseSchema)
	if strings.TrimSpace(query.Statement) == "" {
		return nil, fmt.Errorf("database engine does not support workspace table introspection")
	}
	rows, err := validator.database.QueryContext(ctx, query.Statement, query.Arguments...)
	if err != nil {
		return nil, fmt.Errorf("inventory workspace migration tables: %w", err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		// A borrowed Runtime database contains Runtime-owned workspace tables as
		// well as Identity's prefixed tables. Only inventory this module's
		// relations; passing a Runtime table name through tableIdentifier would
		// incorrectly prefix it and query a relation that does not exist.
		if validator.relationPrefix != "" {
			if !strings.HasPrefix(table, validator.relationPrefix) {
				continue
			}
			table = strings.TrimPrefix(table, validator.relationPrefix)
		}
		tables = append(tables, table)
	}
	sort.Strings(tables)
	return tables, rows.Err()
}
