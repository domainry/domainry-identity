package schema

import (
	"context"
	"fmt"
)

// migrateLegacyIdentityMenuAudience performs the one-way schema cleanup for
// installations created before menus became independent from product surfaces.
func migrateLegacyIdentityMenuAudience(ctx context.Context, store Store) error {
	columns, err := identityMigrationTableColumns(ctx, store, "identity_menus")
	if err != nil {
		return fmt.Errorf("inspect identity_menus for audience migration: %w", err)
	}
	if !columns["audience"] {
		return nil
	}
	query := "ALTER TABLE " + store.TableIdentifier("identity_menus") + " DROP COLUMN " + store.Identifier("audience")
	if _, err := store.SchemaDB().ExecContext(ctx, query); err != nil {
		return fmt.Errorf("drop migrated identity_menus.audience: %w", err)
	}
	return nil
}
