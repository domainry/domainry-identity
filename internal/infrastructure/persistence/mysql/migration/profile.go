package migration

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type Profile struct{}

func NewProfile() Profile { return Profile{} }

func (Profile) MigrationLedgerTypes() driver.MigrationLedgerTypes {
	return driver.MigrationLedgerTypes{Key: "VARCHAR(255)", Timestamp: "VARCHAR(64)"}
}
func (Profile) MigrationBackupPolicy() driver.MigrationBackupPolicy {
	return driver.MigrationBackupPolicy{ExternalEvidence: true, EvidenceEngine: "mysql"}
}
func (Profile) MigrationRollbackPolicy() driver.MigrationRollbackPolicy {
	return driver.MigrationRollbackPolicy{Mode: "restore_external_backup", RequiresVerifiedBackup: true, Procedure: []string{"stop_identity", "restore_verified_database_backup", "restart_identity", "verify_migration_status"}}
}
func (Profile) EnsureMigrationNamespace(context.Context, driver.SchemaDatabase, ormdialect.Renderer, string) error {
	return nil
}
func (Profile) ConfigureMigrationTransaction(context.Context, *sql.Tx, ormdialect.Renderer, string, time.Duration, time.Duration) error {
	return nil
}
func (Profile) AcquireMigrationLock(ctx context.Context, database *sql.DB, renderer ormdialect.Renderer, options driver.MigrationLockOptions) (driver.MigrationLock, error) {
	conn, err := database.Conn(ctx)
	if err != nil {
		return driver.MigrationLock{}, fmt.Errorf("acquire migration connection: %w", err)
	}
	deadline := options.LockTimeout
	if deadline <= 0 {
		deadline = 30 * time.Second
	}
	lockCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	for {
		var result sql.NullInt64
		err = conn.QueryRowContext(lockCtx, "SELECT GET_LOCK("+renderer.Placeholder(1)+", 0)", "domainry_identity_migrations").Scan(&result)
		if err != nil {
			_ = conn.Close()
			return driver.MigrationLock{}, fmt.Errorf("acquire migration lock: %w", err)
		}
		if result.Valid && result.Int64 == 1 {
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
		_, _ = conn.ExecContext(unlockCtx, "SELECT RELEASE_LOCK("+renderer.Placeholder(1)+")", "domainry_identity_migrations")
		_ = conn.Close()
	}}, nil
}

func (Profile) MigrationDatabasePath(config.Config) string { return "" }
