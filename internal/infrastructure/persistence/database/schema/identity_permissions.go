package schema

import (
	"context"
	"fmt"
	"strings"

	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormschema "github.com/domainry/domainry-orm/schema"
)

const identityPermissionsTable = "_identity_permissions"

type identityPermissionIndexSpec struct {
	name    string
	columns []string
}

var identityPermissionIndexSpecs = []identityPermissionIndexSpec{
	{name: "idx_identity_permissions_state", columns: []string{"workspace_id", "definition_status", "enabled"}},
	{name: "idx_identity_permissions_source_owner", columns: []string{"workspace_id", "source_owner"}},
}

func ensureIdentityPermissionsSchema(ctx context.Context, store Store) error {
	renderer := store.SchemaRenderer()
	table := identityPermissionsTableDefinition(renderer)
	statement, arguments, err := table.Build()
	if err != nil {
		return fmt.Errorf("build Identity permission table: %w", err)
	}
	// ORM's typed literal default does not yet parenthesize MySQL TEXT
	// defaults. Reuse the engine's existing physical-definition normalization.
	if _, err := store.SchemaDB().ExecContext(ctx, store.ColumnDefinition(statement), arguments...); err != nil {
		return fmt.Errorf("create Identity permission table: %w", err)
	}
	for _, index := range identityPermissionIndexSpecs {
		if err := ensureIdentityPermissionIndex(ctx, store, index.name, index.columns...); err != nil {
			return err
		}
	}
	return nil
}

func identityPermissionsTableDefinition(renderer ormdialect.Renderer) *ormschema.TableBuilder {
	return ormschema.NewTable(renderer, identityPermissionsTable).
		IfNotExists().
		Columns(
			ormschema.Column("id", ormschema.TextKey(128)).NotNull(),
			ormschema.Column("workspace_id", ormschema.TextKey(128)).NotNull(),
			ormschema.Column("permission_key", ormschema.TextKey(255)).NotNull(),
			ormschema.Column("resource_key", ormschema.TextKey(255)).NotNull(),
			ormschema.Column("operation_key", ormschema.TextKey(128)).NotNull(),
			ormschema.Column("label", ormschema.Text()).NotNull(),
			ormschema.Column("description", ormschema.Text()).NotNull().DefaultValue(""),
			ormschema.Column("category", ormschema.Text()).NotNull(),
			ormschema.Column("source_kind", ormschema.TextKey(64)).NotNull(),
			ormschema.Column("source_owner", ormschema.TextKey(255)).NotNull(),
			ormschema.Column("definition_status", ormschema.TextKey(32)).NotNull(),
			ormschema.Column("enabled", ormschema.Boolean()).NotNull().DefaultValue(true),
			ormschema.Column("definition_hash", ormschema.TextKey(64)).NotNull(),
			ormschema.Column("source_snapshot_hash", ormschema.TextKey(64)).NotNull(),
			ormschema.Column("created_at", ormschema.Text()).NotNull(),
			ormschema.Column("updated_at", ormschema.Text()).NotNull(),
		).
		PrimaryKey("id").
		Unique("workspace_id", "permission_key")
}

func ensureIdentityPermissionIndex(ctx context.Context, store Store, name string, columns ...string) error {
	indexes, err := store.TableIndexes(ctx, identityPermissionsTable)
	if err != nil {
		return fmt.Errorf("inspect Identity permission indexes: %w", err)
	}
	for current := range indexes {
		if strings.EqualFold(current, name) {
			return nil
		}
	}
	index := identityPermissionIndexDefinition(store.SchemaRenderer(), identityPermissionIndexSpec{name: name, columns: columns})
	statement, arguments, err := index.Build()
	if err != nil {
		return fmt.Errorf("build Identity permission index %s: %w", name, err)
	}
	if _, err := store.SchemaDB().ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("create Identity permission index %s: %w", name, err)
	}
	return nil
}

func identityPermissionIndexDefinition(renderer ormdialect.Renderer, spec identityPermissionIndexSpec) *ormschema.IndexBuilder {
	return ormschema.NewIndex(renderer, spec.name, identityPermissionsTable).Columns(spec.columns...)
}
