package migration

func RollbackPolicy(driver string) MigrationRollbackPolicy {
	switch driver {
	case "sqlite":
		return MigrationRollbackPolicy{Mode: "restore_sqlite_backup", RequiresVerifiedBackup: true, Procedure: []string{"stop_identity", "replace_database_with_latest_migration_backup", "restart_identity", "verify_migration_status"}}
	case "postgres":
		return MigrationRollbackPolicy{Mode: "restore_external_backup_or_pitr", RequiresVerifiedBackup: true, Procedure: []string{"stop_identity", "restore_verified_database_backup_or_pitr", "restart_identity", "verify_migration_status"}}
	case "mysql":
		return MigrationRollbackPolicy{Mode: "restore_external_backup", RequiresVerifiedBackup: true, Procedure: []string{"stop_identity", "restore_verified_database_backup", "restart_identity", "verify_migration_status"}}
	default:
		return MigrationRollbackPolicy{Mode: "unsupported", RequiresVerifiedBackup: true}
	}
}
