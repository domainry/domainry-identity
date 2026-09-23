package database

import (
	"context"
	"fmt"
	"strings"

	identitymodulehost "github.com/domainry/domainry-identity-sdk/modulehost"
	metadatasdk "github.com/domainry/domainry-metadata-sdk"
	metadatamodulehost "github.com/domainry/domainry-metadata-sdk/modulehost"
)

// UseHostModuleMigrationRegistrar preserves the embedding Runtime as the sole
// owner of the migration lock and _schema_migrations ledger for nested modules.
func (s *IdentityStore) UseHostModuleMigrationRegistrar(registrar identitymodulehost.MigrationRegistrar) error {
	if s == nil || registrar == nil {
		return fmt.Errorf("embedded module migration registrar is unavailable")
	}
	if strings.TrimSpace(registrar.Driver()) != strings.TrimSpace(s.engine.Name()) || strings.TrimSpace(registrar.Schema()) != strings.TrimSpace(s.databaseSchema) {
		return fmt.Errorf("embedded module migration registrar database identity differs")
	}
	s.hostModuleMigrations = registrar
	return nil
}

func (s *IdentityStore) applyNestedOwnedMigrations(ctx context.Context, owner string, migrations []identitymodulehost.SchemaMigration) error {
	if s.hostModuleMigrations != nil {
		return s.hostModuleMigrations.ApplyOwnedMigrations(ctx, owner, migrations)
	}
	return s.ApplyOwnedMigrations(ctx, owner, migrations)
}

// OpenMetadataModule lets the source-owned Metadata factory apply its own
// migrations through Identity's host registrar, then retains only its SDK
// binding for Identity's metadata repositories.
func (s *IdentityStore) OpenMetadataModule(ctx context.Context, factory metadatasdk.Factory, application metadatasdk.ApplicationRef) (metadatasdk.Binding, error) {
	if s == nil {
		return nil, fmt.Errorf("Identity store is unavailable")
	}
	if factory == nil {
		return nil, fmt.Errorf("Metadata module factory is required")
	}
	if s.metadataBinding != nil {
		return s.metadataBinding, nil
	}
	binding, err := factory.OpenModule(ctx, application, identityMetadataModuleHost{store: s})
	if err != nil {
		return nil, err
	}
	s.metadataBinding = binding
	return binding, nil
}

type identityMetadataModuleHost struct{ store *IdentityStore }

func (h identityMetadataModuleHost) Database() metadatamodulehost.Database {
	return h.store.DB()
}
func (h identityMetadataModuleHost) Dialect() metadatamodulehost.Dialect { return h.store.SQLRenderer }
func (h identityMetadataModuleHost) Migrations() metadatamodulehost.MigrationRegistrar {
	return identityMetadataMigrationRegistrar{store: h.store}
}

type identityMetadataMigrationRegistrar struct{ store *IdentityStore }

func (r identityMetadataMigrationRegistrar) Driver() string { return r.store.engine.Name() }
func (r identityMetadataMigrationRegistrar) Schema() string { return r.store.databaseSchema }
func (r identityMetadataMigrationRegistrar) ApplyOwnedMigrations(ctx context.Context, owner string, migrations []metadatamodulehost.SchemaMigration) error {
	if r.store.hostModuleMigrations != nil {
		return r.store.hostModuleMigrations.ApplyOwnedMigrations(ctx, owner, migrations)
	}
	if r.store.borrowedDatabase {
		return r.store.ApplyOwnedMigrations(ctx, owner, migrations)
	}
	return r.store.ApplyOwnedMigrationsLocked(ctx, owner, migrations)
}
