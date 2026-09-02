package schema

import (
	"context"
	"fmt"

	ormschema "github.com/domainry/domainry-orm/schema"
)

// migrateLegacyIdentityMenuAudience performs the one-way schema cleanup for
// installations created before menus became independent from product surfaces.
func migrateLegacyIdentityMenuAudience(ctx context.Context, store Store) error {
	columns, err := store.TableColumns(ctx, "_identity_menus")
	if err != nil {
		return fmt.Errorf("inspect _identity_menus for audience migration: %w", err)
	}
	if !columns["audience"] {
		return nil
	}
	statement, arguments, buildErr := ormschema.NewDropColumn(store.SchemaRenderer(), "_identity_menus", "audience").Build()
	if buildErr != nil {
		return fmt.Errorf("build migrated _identity_menus.audience removal: %w", buildErr)
	}
	if _, err := store.SchemaDB().ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("drop migrated _identity_menus.audience: %w", err)
	}
	return nil
}
