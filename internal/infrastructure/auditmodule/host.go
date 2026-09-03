package auditmodule

import (
	"context"

	"github.com/domainry/domainry-audit-sdk/modulehost"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
)

type Host struct {
	store  *database.IdentityStore
	locked bool
}

func NewHost(store *database.IdentityStore) Host       { return Host{store: store} }
func NewLockedHost(store *database.IdentityStore) Host { return Host{store: store, locked: true} }
func (h Host) Database() modulehost.Database           { return h.store.DB() }
func (h Host) Dialect() modulehost.Dialect             { return h.store.BuilderRenderer() }
func (h Host) Migrations() modulehost.MigrationRegistrar {
	return migrationRegistrar{store: h.store, locked: h.locked}
}

type migrationRegistrar struct {
	store  *database.IdentityStore
	locked bool
}

func (r migrationRegistrar) Driver() string { return r.store.PersistenceEngine().Name() }
func (r migrationRegistrar) Schema() string { return r.store.DatabaseSchema() }
func (r migrationRegistrar) ApplyOwnedMigrations(ctx context.Context, owner string, migrations []modulehost.SchemaMigration) error {
	if r.locked {
		return r.store.ApplyOwnedMigrationsLocked(ctx, owner, migrations)
	}
	return r.store.ApplyNestedOwnedMigrations(ctx, owner, migrations)
}
