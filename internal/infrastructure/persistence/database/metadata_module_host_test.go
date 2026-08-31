package database

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestIdentityMetadataModuleUsesBusinessDatabaseWhileRegistrarOwnsMigrations(t *testing.T) {
	business, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = business.Close() })
	migration, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migration.Close() })

	store := &IdentityStore{db: business, migrationDB: migration}
	host := identityMetadataModuleHost{store: store}
	if host.Database() != business {
		t.Fatal("Metadata business Binding must not retain the privileged migration pool")
	}
}
