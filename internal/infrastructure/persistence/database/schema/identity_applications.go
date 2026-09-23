package schema

import (
	"context"
	"fmt"

	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormschema "github.com/domainry/domainry-orm/schema"
)

const identityApplicationsTable = "_identity_applications"

func ensureIdentityApplicationsSchema(ctx context.Context, store Store) error {
	statement, arguments, err := identityApplicationsTableDefinition(store.SchemaRenderer()).Build()
	if err != nil {
		return fmt.Errorf("build Identity applications table: %w", err)
	}
	if _, err := store.SchemaDB().ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("create Identity applications table: %w", err)
	}
	return nil
}

func identityApplicationsTableDefinition(renderer ormdialect.Renderer) *ormschema.TableBuilder {
	return ormschema.NewTable(renderer, identityApplicationsTable).
		IfNotExists().
		Columns(
			ormschema.Column("id", ormschema.TextKey(128)).NotNull(),
			ormschema.Column("workspace_id", ormschema.TextKey(128)).NotNull(),
			ormschema.Column("application_key", ormschema.TextKey(255)).NotNull(),
			ormschema.Column("redirect_urls_json", ormschema.Text()).NotNull(),
			ormschema.Column("status", ormschema.TextKey(32)).NotNull(),
			ormschema.Column("created_at", ormschema.Text()).NotNull(),
			ormschema.Column("updated_at", ormschema.Text()).NotNull(),
		).
		PrimaryKey("workspace_id", "id").
		Unique("workspace_id", "application_key")
}
