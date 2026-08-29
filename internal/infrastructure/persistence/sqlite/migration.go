package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/filelock"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (Dialect) MigrationLedgerTypes() driver.MigrationLedgerTypes {
	return driver.MigrationLedgerTypes{Key: "TEXT", Timestamp: "TEXT"}
}
func (Dialect) MigrationBackupPolicy() driver.MigrationBackupPolicy {
	return driver.MigrationBackupPolicy{LocalSnapshot: true, EvidenceEngine: "sqlite", BackupIDPrefix: "sqlite-"}
}
func (Dialect) MigrationRollbackPolicy() driver.MigrationRollbackPolicy {
	return driver.MigrationRollbackPolicy{
		Mode: "restore_sqlite_backup", RequiresVerifiedBackup: true,
		Procedure: []string{"stop_identity", "replace_database_with_latest_migration_backup", "restart_identity", "verify_migration_status"},
	}
}
func (Dialect) EnsureMigrationNamespace(context.Context, driver.SchemaDatabase, ormdialect.Renderer, string) error {
	return nil
}
func (Dialect) ConfigureMigrationTransaction(context.Context, *sql.Tx, ormdialect.Renderer, string, time.Duration, time.Duration) error {
	return nil
}
func (Dialect) AcquireMigrationLock(ctx context.Context, _ *sql.DB, _ ormdialect.Renderer, options driver.MigrationLockOptions) (driver.MigrationLock, error) {
	path := strings.TrimSpace(options.DatabasePath)
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return driver.MigrationLock{Release: func() {}}, nil
	}
	lockPath := path + ".migration.lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return driver.MigrationLock{}, err
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return driver.MigrationLock{}, fmt.Errorf("open sqlite migration lock: %w", err)
	}
	deadline := options.LockTimeout
	if deadline <= 0 {
		deadline = 30 * time.Second
	}
	lockCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	for {
		err = filelock.TryExclusive(file)
		if err == nil {
			break
		}
		select {
		case <-lockCtx.Done():
			_ = file.Close()
			return driver.MigrationLock{}, fmt.Errorf("migration.lock_timeout: owner=%s timeout=%s: %w", options.Owner, deadline, lockCtx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	owner := options.Owner + " acquired_at=" + time.Now().UTC().Format(time.RFC3339Nano)
	_ = file.Truncate(0)
	_, _ = file.WriteString(owner)
	return driver.MigrationLock{Release: func() { _ = filelock.Unlock(file); _ = file.Close() }}, nil
}

func (Dialect) MigrationDatabasePath(cfg config.Config) string {
	if value := strings.TrimSpace(cfg.DBPath); value != "" {
		return value
	}
	return strings.TrimSpace(cfg.DatabaseDSN)
}
