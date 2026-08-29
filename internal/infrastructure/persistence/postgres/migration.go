package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (Dialect) MigrationLedgerTypes() driver.MigrationLedgerTypes {
	return driver.MigrationLedgerTypes{Key: "TEXT", Timestamp: "TEXT"}
}
func (Dialect) MigrationBackupPolicy() driver.MigrationBackupPolicy {
	return driver.MigrationBackupPolicy{EvidenceEngine: "postgres"}
}
func (Dialect) MigrationRollbackPolicy() driver.MigrationRollbackPolicy {
	return driver.MigrationRollbackPolicy{
		Mode: "restore_external_backup_or_pitr", RequiresVerifiedBackup: true,
		Procedure: []string{"stop_identity", "restore_verified_database_backup_or_pitr", "restart_identity", "verify_migration_status"},
	}
}
func (Dialect) EnsureMigrationNamespace(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, databaseSchema string) error {
	if strings.TrimSpace(databaseSchema) == "" || strings.EqualFold(databaseSchema, "public") {
		return nil
	}
	if _, err := database.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS "+renderer.Identifier(databaseSchema)); err != nil {
		return fmt.Errorf("prepare PostgreSQL Identity schema: %w", err)
	}
	return nil
}
func (Dialect) ConfigureMigrationTransaction(ctx context.Context, transaction *sql.Tx, renderer ormdialect.Renderer, databaseSchema string, lockTimeout, statementTimeout time.Duration) error {
	if _, err := transaction.ExecContext(ctx, "SELECT set_config('search_path', "+renderer.Placeholder(1)+", true)", databaseSchema); err != nil {
		return fmt.Errorf("set migration schema search path: %w", err)
	}
	if lockTimeout > 0 {
		if _, err := transaction.ExecContext(ctx, "SELECT set_config('lock_timeout', "+renderer.Placeholder(1)+", true)", fmt.Sprintf("%dms", lockTimeout.Milliseconds())); err != nil {
			return fmt.Errorf("set migration lock timeout: %w", err)
		}
	}
	if statementTimeout > 0 {
		if _, err := transaction.ExecContext(ctx, "SELECT set_config('statement_timeout', "+renderer.Placeholder(1)+", true)", fmt.Sprintf("%dms", statementTimeout.Milliseconds())); err != nil {
			return fmt.Errorf("set migration statement timeout: %w", err)
		}
	}
	return nil
}
func (Dialect) AcquireMigrationLock(ctx context.Context, database *sql.DB, renderer ormdialect.Renderer, options driver.MigrationLockOptions) (driver.MigrationLock, error) {
	conn, err := database.Conn(ctx)
	if err != nil {
		return driver.MigrationLock{}, fmt.Errorf("acquire migration connection: %w", err)
	}
	key := "domainry_identity_migrations:" + options.DatabaseSchema
	deadline := options.LockTimeout
	if deadline <= 0 {
		deadline = 30 * time.Second
	}
	lockCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	for {
		var locked bool
		err = conn.QueryRowContext(lockCtx, "SELECT pg_try_advisory_lock(hashtextextended("+renderer.Placeholder(1)+", 0))", key).Scan(&locked)
		if err != nil {
			_ = conn.Close()
			return driver.MigrationLock{}, fmt.Errorf("acquire migration lock: %w", err)
		}
		if locked {
			break
		}
		select {
		case <-lockCtx.Done():
			_ = conn.Close()
			return driver.MigrationLock{}, fmt.Errorf("migration.lock_timeout: owner=%s timeout=%s: %w", options.Owner, deadline, lockCtx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	return driver.MigrationLock{Connection: conn, Release: func() {
		timeout := options.ConnectTimeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		unlockCtx, unlockCancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer unlockCancel()
		_, _ = conn.ExecContext(unlockCtx, "SELECT pg_advisory_unlock(hashtextextended("+renderer.Placeholder(1)+", 0))", key)
		_ = conn.Close()
	}}, nil
}

func (Dialect) MigrationDatabasePath(config.Config) string { return "" }
