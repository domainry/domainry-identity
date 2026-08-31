package database

import (
	"context"

	metadatasdk "github.com/domainry/domainry-metadata-sdk"
	metadatamodulehost "github.com/domainry/domainry-metadata-sdk/modulehost"
	metadatamodule "github.com/domainry/domainry-metadata/module"
)

func (s *IdentityStore) ensureMetadataModuleSchema(ctx context.Context) error {
	binding, err := metadatamodule.NewFactory().OpenModule(ctx, metadatasdk.ApplicationRef{InstallationID: "domainry-identity"}, identityMetadataModuleHost{store: s})
	if err != nil {
		return err
	}
	s.metadataBinding = binding
	return nil
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
	return r.store.ApplyOwnedMigrationsLocked(ctx, owner, migrations)
}
