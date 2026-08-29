package database

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/base"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
)

func attachBackupManager(store *IdentityStore, checksum func(string) (string, error)) {
	database := store.db
	if store.migrationDB != nil {
		database = store.migrationDB
	}
	renderer := base.NewSQLDatabase(database, store.engine, store.databaseSchema, store.relationPrefix).SQLRenderer
	store.BackupManager = migration.NewBackupManager(migration.BackupOptions{
		Database: database, Engine: store.engine, Renderer: renderer, DatabaseSchema: store.databaseSchema,
		RelationPrefix: store.relationPrefix, SecretMaterialKey: store.secretMaterialKey,
		Metrics: store.operationalMetrics, Checksum: checksum,
	})
}
