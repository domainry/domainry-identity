package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	migrationcontract "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func (s *IdentityStore) applyMigrations(ctx context.Context, cfg config.Config) error {
	release, err := s.acquireMigrationLock(ctx, cfg)
	if err != nil {
		return err
	}
	defer release()
	if err := s.ensureMigrationLedger(ctx); err != nil {
		return fmt.Errorf("prepare schema migration table: %w", err)
	}
	paths, err := s.migrationPaths(cfg)
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	if err := s.setExpectedMigrations(paths); err != nil {
		return err
	}
	backupChecked := false
	for _, path := range paths {
		pending, err := s.migrationPending(ctx, path)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", path, err)
		}
		if pending && !backupChecked {
			if err := s.ensureMigrationBackupForExistingData(ctx, cfg); err != nil {
				return err
			}
			backupChecked = true
		}
		if err := s.applyMigrationFile(ctx, path); err != nil {
			return fmt.Errorf("apply migration %s: %w", path, err)
		}
	}
	status, err := s.MigrationStatus(ctx)
	if err != nil {
		return err
	}
	if !status.Current {
		return fmt.Errorf("%s: database schema is not compatible with Identity service %s", status.ErrorCode, strings.TrimSpace(s.config.ServiceVersion))
	}
	return nil
}

func (s *IdentityStore) verifyMigrations(ctx context.Context, cfg config.Config) error {
	paths, err := s.migrationPaths(cfg)
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	if err := s.setExpectedMigrations(paths); err != nil {
		return err
	}
	for _, path := range paths {
		if err := s.verifyMigration(ctx, path); err != nil {
			return fmt.Errorf("verify migration %s: %w", filepath.Base(path), err)
		}
	}
	status, err := s.MigrationStatus(ctx)
	if err != nil {
		return err
	}
	if !status.Current {
		return fmt.Errorf("%s: database schema is not compatible with Identity service %s", status.ErrorCode, strings.TrimSpace(s.config.ServiceVersion))
	}
	return nil
}

func (s *IdentityStore) verifyMigration(ctx context.Context, path string) error {
	name := filepath.Base(path)
	expected, err := migrationcontract.Checksum(path)
	if err != nil {
		return err
	}
	var applied string
	var dirty bool
	query := "SELECT " + s.identifier("checksum") + ", " + s.identifier("dirty") + " FROM " + s.tableIdentifier("_schema_migrations") + " WHERE " + s.identifier("path") + " = " + s.placeholder(1)
	err = s.db.QueryRowContext(ctx, query, name).Scan(&applied, &dirty)
	if err == sql.ErrNoRows {
		return fmt.Errorf("migration.pending: %s", name)
	}
	if err != nil {
		return err
	}
	if dirty {
		return fmt.Errorf("migration.dirty: %s", name)
	}
	if strings.TrimSpace(applied) == "" {
		return fmt.Errorf("migration.checksum_drift: checksum missing for %s", name)
	}
	if applied != expected {
		return fmt.Errorf("migration.checksum_drift: %s", name)
	}
	return nil
}

func (s *IdentityStore) migrationPending(ctx context.Context, path string) (bool, error) {
	name := filepath.Base(path)
	expected, err := migrationcontract.Checksum(path)
	if err != nil {
		return false, err
	}
	var applied string
	var dirty bool
	query := "SELECT " + s.identifier("checksum") + ", " + s.identifier("dirty") + " FROM " + s.tableIdentifier("_schema_migrations") + " WHERE " + s.identifier("path") + " = " + s.placeholder(1)
	err = s.schemaDatabase().QueryRowContext(ctx, query, name).Scan(&applied, &dirty)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if dirty {
		return false, fmt.Errorf("migration.dirty: %s", name)
	}
	if strings.TrimSpace(applied) == "" {
		update := "UPDATE " + s.tableIdentifier("_schema_migrations") + " SET " + s.identifier("checksum") + " = " + s.placeholder(1) + " WHERE " + s.identifier("path") + " = " + s.placeholder(2)
		if _, err := s.schemaDatabase().ExecContext(ctx, update, expected, name); err != nil {
			return false, fmt.Errorf("backfill migration checksum: %w", err)
		}
		return false, nil
	}
	if applied != expected {
		return false, fmt.Errorf("migration.checksum_drift: %s", name)
	}
	return false, nil
}

func (s *IdentityStore) applyMigrationFile(ctx context.Context, path string) error {
	startedAt := time.Now()
	name := filepath.Base(path)
	pending, err := s.migrationPending(ctx, path)
	if err != nil {
		return err
	}
	if !pending {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	checksum := migrationcontract.ChecksumBytes(raw)
	version, migrationName := migrationcontract.Identity(name)
	insertDirty := "INSERT INTO " + s.tableIdentifier("_schema_migrations") + " (" + migrationColumns(s) + ") VALUES (" + strings.Join(placeholders(s, 12), ", ") + ")"
	if _, err := s.schemaDatabase().ExecContext(ctx, insertDirty, name, version, migrationName, migrationcontract.Kind(migrationName), checksum, true, time.Now().UTC().Format(time.RFC3339), strings.TrimSpace(s.config.ServiceVersion), 0, migrationcontract.Operator(s.config), migrationcontract.InstanceID(s.config), strings.TrimSpace(s.migrationBackupID)); err != nil {
		return fmt.Errorf("record dirty migration: %w", err)
	}
	tx, err := s.schemaDatabase().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	base := s.sqlBase()
	if err := base.Engine.ConfigureMigrationTransaction(ctx, tx, base.SQLRenderer, base.DatabaseSchema, s.config.DatabaseLockTimeout, s.config.DatabaseStatementTimeout); err != nil {
		return err
	}
	for _, statement := range migrationcontract.SplitSQLStatements(string(raw)) {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migration.failed: execute %s: %w", name, err)
		}
	}
	duration := time.Since(startedAt)
	completeMigration := "UPDATE " + s.tableIdentifier("_schema_migrations") + " SET " + s.identifier("dirty") + " = FALSE, " + s.identifier("duration_ms") + " = " + s.placeholder(1) + ", " + s.identifier("applied_at") + " = " + s.placeholder(2) + " WHERE " + s.identifier("path") + " = " + s.placeholder(3) + " AND " + s.identifier("checksum") + " = " + s.placeholder(4)
	if _, err := tx.ExecContext(ctx, completeMigration, duration.Milliseconds(), time.Now().UTC().Format(time.RFC3339), name, checksum); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func (s *IdentityStore) schemaMigrationSQL() string {
	types := s.sqlBase().Engine.MigrationLedgerTypes()
	pathType := types.Key
	timeType := types.Timestamp
	return "CREATE TABLE IF NOT EXISTS " + s.tableIdentifier("_schema_migrations") + " (" + s.identifier("path") + " " + pathType + " PRIMARY KEY, " + s.identifier("version") + " " + pathType + " NOT NULL DEFAULT '', " + s.identifier("name") + " " + pathType + " NOT NULL DEFAULT '', " + s.identifier("kind") + " " + pathType + " NOT NULL DEFAULT 'schema', " + s.identifier("checksum") + " " + pathType + " NOT NULL DEFAULT '', " + s.identifier("dirty") + " BOOLEAN NOT NULL DEFAULT FALSE, " + s.identifier("applied_at") + " " + timeType + " NOT NULL, " + s.identifier("service_version") + " " + pathType + " NOT NULL DEFAULT '', " + s.identifier("duration_ms") + " BIGINT NOT NULL DEFAULT 0, " + s.identifier("operator") + " " + pathType + " NOT NULL DEFAULT '', " + s.identifier("instance_id") + " " + pathType + " NOT NULL DEFAULT '', " + s.identifier("backup_id") + " " + pathType + " NOT NULL DEFAULT '')"
}

func (s *IdentityStore) ensureMigrationLedger(ctx context.Context) error {
	db := s.schemaDatabase()
	base := s.sqlBase()
	if err := base.Engine.EnsureMigrationNamespace(ctx, db, base.SQLRenderer, base.DatabaseSchema); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, s.schemaMigrationSQL()); err != nil {
		return err
	}
	textType := base.Engine.MigrationLedgerTypes().Key + " NOT NULL DEFAULT ''"
	columns := []struct{ name, definition string }{
		{"version", textType}, {"name", textType}, {"kind", textType}, {"checksum", textType},
		{"dirty", "BOOLEAN NOT NULL DEFAULT FALSE"}, {"service_version", textType}, {"duration_ms", "BIGINT NOT NULL DEFAULT 0"},
		{"operator", textType}, {"instance_id", textType}, {"backup_id", textType},
	}
	for _, column := range columns {
		rows, queryErr := db.QueryContext(ctx, "SELECT "+s.identifier(column.name)+" FROM "+s.tableIdentifier("_schema_migrations")+" WHERE 1 = 0")
		if queryErr == nil {
			_ = rows.Close()
			continue
		}
		if _, alterErr := db.ExecContext(ctx, "ALTER TABLE "+s.tableIdentifier("_schema_migrations")+" ADD COLUMN "+s.identifier(column.name)+" "+column.definition); alterErr != nil {
			return alterErr
		}
	}
	return nil
}

func (s *IdentityStore) acquireMigrationLock(ctx context.Context, cfg config.Config) (func(), error) {
	lockDB := s.migrationDB
	if lockDB == nil {
		lockDB = s.db
	}
	started := time.Now()
	base := s.sqlBase()
	lock, err := base.Engine.AcquireMigrationLock(ctx, lockDB, base.SQLRenderer, driver.MigrationLockOptions{
		DatabasePath: cfg.DBPath, DatabaseSchema: base.DatabaseSchema, Owner: migrationcontract.InstanceID(cfg),
		LockTimeout: s.config.DatabaseLockTimeout, ConnectTimeout: s.config.DatabaseConnectTimeout,
	})
	if err != nil {
		return nil, err
	}
	s.migrationConn = lock.Connection
	if s.operationalMetrics != nil {
		s.operationalMetrics.ObserveMigrationLock(time.Since(started), err)
	}
	return func() {
		s.migrationConn = nil
		if lock.Release != nil {
			lock.Release()
		}
	}, nil
}

func migrationColumns(s *IdentityStore) string {
	columns := []string{"path", "version", "name", "kind", "checksum", "dirty", "applied_at", "service_version", "duration_ms", "operator", "instance_id", "backup_id"}
	return strings.Join(quotedColumns(s, columns), ", ")
}

func (s *IdentityStore) migrationPaths(cfg config.Config) ([]string, error) {
	if strings.TrimSpace(cfg.MigrationSQL) != "" {
		return []string{cfg.MigrationSQL}, nil
	}
	driverDir := filepath.Join(cfg.MigrationDir, s.engine.Name())
	if entries, err := s.readMigrationDir(driverDir); err == nil {
		return migrationcontract.SQLPaths(driverDir, entries), nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	entries, err := s.readMigrationDir(cfg.MigrationDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return migrationcontract.SQLPaths(cfg.MigrationDir, entries), nil
}

func (s *IdentityStore) readMigrationDir(path string) ([]os.DirEntry, error) {
	if s.migrationReadDir != nil {
		return s.migrationReadDir(path)
	}
	return os.ReadDir(path)
}

func (s *IdentityStore) setExpectedMigrations(paths []string) error {
	expectedPaths := migrationcontract.Names(paths)
	expectedChecksums := make(map[string]string, len(paths))
	for _, path := range paths {
		checksum, err := migrationcontract.Checksum(path)
		if err != nil {
			return err
		}
		expectedChecksums[filepath.Base(path)] = checksum
	}
	if s.StatusReader == nil {
		s.StatusReader = migrationcontract.NewStatusReader(s.schemaDatabase(), s.engine, s.BuilderRenderer(), s.config)
	}
	s.StatusReader.ReplaceExpected(expectedPaths, expectedChecksums)
	return nil
}
