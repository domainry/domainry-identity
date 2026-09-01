package role

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistencedriver "github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	mysqlpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql"
	postgrespersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	sqlitepersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type roleBatchRenderBackend struct {
	engine   persistencedriver.Engine
	renderer ormdialect.Renderer
}

func (backend roleBatchRenderBackend) DB() *sql.DB { return nil }
func (backend roleBatchRenderBackend) SQLRenderer() ormdialect.Renderer {
	return backend.renderer
}
func (backend roleBatchRenderBackend) MaxParameters() int { return backend.engine.MaxParameters() }
func (backend roleBatchRenderBackend) ApplyUpsert(builder *query.InsertBuilder, conflictColumns []string, updateColumns ...string) *query.InsertBuilder {
	return backend.engine.ApplyUpsert(builder, conflictColumns, updateColumns...)
}
func (roleBatchRenderBackend) QueryIdentityContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, nil
}

type roleBatchCaptureExecer struct {
	statements []string
	arguments  [][]any
}

func (execer *roleBatchCaptureExecer) ExecContext(_ context.Context, statement string, arguments ...any) (sql.Result, error) {
	execer.statements = append(execer.statements, statement)
	execer.arguments = append(execer.arguments, append([]any(nil), arguments...))
	return driver.RowsAffected(2), nil
}

func TestRoleUpsertUsesMultiRowStatementAcrossDialects(t *testing.T) {
	for _, test := range []struct {
		name           string
		engine         persistencedriver.Engine
		conflictMarker string
	}{
		{name: "sqlite", engine: sqlitepersistence.NewEngine(), conflictMarker: " ON CONFLICT "},
		{name: "mysql", engine: mysqlpersistence.NewEngine(), conflictMarker: " ON DUPLICATE KEY UPDATE "},
		{name: "postgres", engine: postgrespersistence.NewEngine(), conflictMarker: " ON CONFLICT "},
	} {
		t.Run(test.name, func(t *testing.T) {
			renderer, err := test.engine.SQLDialect().WithNamespace(test.engine.RendererSchema("identity"), "")
			if err != nil {
				t.Fatal(err)
			}
			store := New(roleBatchRenderBackend{engine: test.engine, renderer: renderer}, func() string { return "now" })
			execer := &roleBatchCaptureExecer{}
			err = store.UpsertBatchWithExecutor(t.Context(), execer, "workspace-primary", []identitymodel.IdentityRole{
				{ID: "role-one", Key: "one", Label: "One"},
				{ID: "role-two", Key: "two", Label: "Two"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(execer.statements) != 1 || len(execer.arguments) != 1 || len(execer.arguments[0]) != 16 {
				t.Fatalf("role upsert writes=%d args=%v", len(execer.statements), execer.arguments)
			}
			statement := execer.statements[0]
			if strings.Count(statement, "), (") != 1 || !strings.Contains(statement, test.conflictMarker) {
				t.Fatalf("role upsert is not one dialect-aware two-row statement: %s", statement)
			}
			conflict := strings.SplitN(statement, test.conflictMarker, 2)
			if len(conflict) != 2 || strings.Contains(conflict[1], renderer.Identifier("created_at")+" =") {
				t.Fatalf("role upsert overwrites creation time: %s", statement)
			}
		})
	}
}
