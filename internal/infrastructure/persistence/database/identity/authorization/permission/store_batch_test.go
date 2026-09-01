package permission

import (
	"context"
	"database/sql"
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

type permissionBatchRenderBackend struct {
	engine   persistencedriver.Engine
	renderer ormdialect.Renderer
}

func (backend permissionBatchRenderBackend) DB() *sql.DB { return nil }
func (backend permissionBatchRenderBackend) SQLRenderer() ormdialect.Renderer {
	return backend.renderer
}
func (backend permissionBatchRenderBackend) MaxParameters() int {
	return backend.engine.MaxParameters()
}
func (backend permissionBatchRenderBackend) ApplyUpsert(builder *query.InsertBuilder, conflictColumns []string, updateColumns ...string) *query.InsertBuilder {
	return backend.engine.ApplyUpsert(builder, conflictColumns, updateColumns...)
}
func (permissionBatchRenderBackend) QueryIdentityContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, nil
}

func TestPermissionReconcileUsesMultiRowUpsertAcrossDialects(t *testing.T) {
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
			backend := permissionBatchRenderBackend{engine: test.engine, renderer: renderer}
			definitions := map[string]identitymodel.IdentityPermissionDefinitionRecord{
				"permission.one": permissionBatchDefinition("permission.one"),
				"permission.two": permissionBatchDefinition("permission.two"),
			}
			statement, arguments, err := permissionUpsertBuilder(backend, "workspace-primary", []string{"permission.one", "permission.two"}, definitions, "now").Build()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(statement, "), (") != 1 || len(arguments) != 32 {
				t.Fatalf("permission upsert is not one two-row batch: sql=%s args=%d", statement, len(arguments))
			}
			parts := strings.SplitN(statement, test.conflictMarker, 2)
			if len(parts) != 2 {
				t.Fatalf("permission upsert is missing dialect conflict handling: %s", statement)
			}
			if strings.Contains(parts[1], renderer.Identifier("enabled")+" =") || strings.Contains(parts[1], renderer.Identifier("created_at")+" =") {
				t.Fatalf("permission upsert overwrites administrator state or creation time: %s", statement)
			}
		})
	}
}

func permissionBatchDefinition(key string) identitymodel.IdentityPermissionDefinitionRecord {
	return identitymodel.IdentityPermissionDefinitionRecord{
		PermissionKey: key, ResourceKey: "roles", ActionKey: "read", Label: key,
		Category: "Identity", SourceKind: "builtin_surface", SourceOwner: "identity:builtin",
		DefinitionHash: "definition-hash", SourceSnapshotHash: "snapshot-hash",
	}
}
