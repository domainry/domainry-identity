package database

import (
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/base"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
)

func attachBackupManager(store *IdentityStore, checksum func(string) (string, error)) {
	ensureCoordinator(store)
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

func attachLockManager(store *IdentityStore) {
	ensureCoordinator(store)
	database := store.db
	if store.migrationDB != nil {
		database = store.migrationDB
	}
	renderer := base.NewSQLDatabase(database, store.engine, store.databaseSchema, store.relationPrefix).SQLRenderer
	store.LockManager = migration.NewLockManager(database, store.engine, renderer, store.databaseSchema, store.config, store.operationalMetrics)
}

func attachLedger(store *IdentityStore) {
	ensureCoordinator(store)
	database := store.db
	if store.migrationDB != nil {
		database = store.migrationDB
	}
	renderer := base.NewSQLDatabase(database, store.engine, store.databaseSchema, store.relationPrefix).SQLRenderer
	store.Ledger = migration.NewLedger(database, store.engine, renderer, store.databaseSchema)
}

func attachPathResolver(store *IdentityStore, readDir migration.ReadDirFunc) {
	ensureCoordinator(store)
	store.PathResolver = migration.NewPathResolver(store.engine, readDir)
}

func ensureCoordinator(store *IdentityStore) {
	if store.Coordinator == nil {
		store.Coordinator = &migration.Coordinator{}
	}
}

func attachCoordinator(store *IdentityStore) {
	database := store.db
	if store.migrationDB != nil {
		database = store.migrationDB
	}
	renderer := base.NewSQLDatabase(database, store.engine, store.databaseSchema, store.relationPrefix).SQLRenderer
	ensureCoordinator(store)
	if store.StatusReader == nil {
		store.StatusReader = migration.NewStatusReader(database, store.engine, renderer, store.config)
	}
	if store.BackupManager == nil {
		attachBackupManager(store, nil)
	}
	if store.LockManager == nil {
		attachLockManager(store)
	}
	if store.Ledger == nil {
		attachLedger(store)
	}
	if store.PathResolver == nil {
		attachPathResolver(store, nil)
	}
	store.Coordinator = migration.NewCoordinator(migration.CoordinatorOptions{
		QueryDatabase: store.db, ManagementDatabase: database,
		Engine: store.engine, Renderer: renderer, DatabaseSchema: store.databaseSchema, Config: store.config,
		StatusReader: store.StatusReader, BackupManager: store.BackupManager, LockManager: store.LockManager,
		Ledger: store.Ledger, PathResolver: store.PathResolver,
	})
}
