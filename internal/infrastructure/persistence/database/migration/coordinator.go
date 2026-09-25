package migration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Database interface {
	driver.SchemaDatabase
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type CoordinatorOptions struct {
	QueryDatabase      *sql.DB
	ManagementDatabase Database
	Engine             driver.Engine
	Renderer           ormdialect.Renderer
	DatabaseSchema     string
	Config             config.Config
	StatusReader       *StatusReader
	BackupManager      *BackupManager
	LockManager        *LockManager
	Ledger             *Ledger
	PathResolver       *PathResolver
}

type Coordinator struct {
	*StatusReader
	*BackupManager
	*LockManager
	*Ledger
	*PathResolver
	queryDatabase      *sql.DB
	managementDatabase Database
	engine             driver.Engine
	renderer           ormdialect.Renderer
	databaseSchema     string
	config             config.Config
}

func NewCoordinator(options CoordinatorOptions) *Coordinator {
	return &Coordinator{
		StatusReader: options.StatusReader, BackupManager: options.BackupManager,
		LockManager: options.LockManager, Ledger: options.Ledger, PathResolver: options.PathResolver,
		queryDatabase: options.QueryDatabase, managementDatabase: options.ManagementDatabase,
		engine: options.Engine, renderer: options.Renderer, databaseSchema: options.DatabaseSchema, config: options.Config,
	}
}

func (coordinator *Coordinator) Apply(ctx context.Context, cfg config.Config) error {
	release, err := coordinator.LockManager.Acquire(ctx, cfg)
	if err != nil {
		return err
	}
	defer release()
	if err := coordinator.Ledger.Ensure(ctx); err != nil {
		return fmt.Errorf("prepare schema migration table: %w", err)
	}
	paths, err := coordinator.PathResolver.Paths(cfg)
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	if err := coordinator.SetExpected(paths); err != nil {
		return err
	}
	backupChecked := false
	for _, path := range paths {
		pending, err := coordinator.Pending(ctx, path)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", path, err)
		}
		if pending && !backupChecked {
			if err := coordinator.BackupManager.EnsureForExistingData(ctx, cfg); err != nil {
				return err
			}
			backupChecked = true
		}
		if err := coordinator.ApplyFile(ctx, path); err != nil {
			return fmt.Errorf("apply migration %s: %w", path, err)
		}
	}
	status, err := coordinator.MigrationStatus(ctx)
	if err != nil {
		return err
	}
	if !status.Current {
		return fmt.Errorf("%s: database schema is not compatible with Identity service %s", status.ErrorCode, strings.TrimSpace(coordinator.config.ServiceVersion))
	}
	return nil
}

func (coordinator *Coordinator) Verify(ctx context.Context, cfg config.Config) error {
	paths, err := coordinator.PathResolver.Paths(cfg)
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	if err := coordinator.SetExpected(paths); err != nil {
		return err
	}
	for _, path := range paths {
		if err := coordinator.VerifyFile(ctx, path); err != nil {
			return fmt.Errorf("verify migration %s: %w", filepath.Base(path), err)
		}
	}
	status, err := coordinator.MigrationStatus(ctx)
	if err != nil {
		return err
	}
	if !status.Current {
		return fmt.Errorf("%s: database schema is not compatible with Identity service %s", status.ErrorCode, strings.TrimSpace(coordinator.config.ServiceVersion))
	}
	return nil
}

func (coordinator *Coordinator) VerifyFile(ctx context.Context, path string) error {
	name := filepath.Base(path)
	expected, err := Checksum(path)
	if err != nil {
		return err
	}
	var applied string
	var dirty bool
	statement, arguments, buildErr := query.NewSelectBuilder(coordinator.renderer, "_schema_migrations").
		Columns("checksum", "dirty").Where(query.Equal("path", name)).Limit(1).Build()
	if buildErr != nil {
		return fmt.Errorf("build migration verification: %w", buildErr)
	}
	err = coordinator.queryDatabase.QueryRowContext(ctx, statement, arguments...).Scan(&applied, &dirty)
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

func (coordinator *Coordinator) Pending(ctx context.Context, path string) (bool, error) {
	name := filepath.Base(path)
	expected, err := Checksum(path)
	if err != nil {
		return false, err
	}
	var applied string
	var dirty bool
	statement, arguments, buildErr := query.NewSelectBuilder(coordinator.renderer, "_schema_migrations").
		Columns("checksum", "dirty").Where(query.Equal("path", name)).Limit(1).Build()
	if buildErr != nil {
		return false, fmt.Errorf("build pending migration lookup: %w", buildErr)
	}
	err = coordinator.managementDatabase.QueryRowContext(ctx, statement, arguments...).Scan(&applied, &dirty)
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
		update, updateArguments, buildErr := query.NewUpdateBuilder(coordinator.renderer, "_schema_migrations").
			Set("checksum", expected).Where(query.Equal("path", name)).Build()
		if buildErr != nil {
			return false, fmt.Errorf("build migration checksum backfill: %w", buildErr)
		}
		if _, err := coordinator.managementDatabase.ExecContext(ctx, update, updateArguments...); err != nil {
			return false, fmt.Errorf("backfill migration checksum: %w", err)
		}
		return false, nil
	}
	if applied != expected {
		return false, fmt.Errorf("migration.checksum_drift: %s", name)
	}
	return false, nil
}

func (coordinator *Coordinator) ApplyFile(ctx context.Context, path string) error {
	startedAt := time.Now()
	name := filepath.Base(path)
	pending, err := coordinator.Pending(ctx, path)
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
	checksum := ChecksumBytes(raw)
	version, migrationName := Identity(name)
	insertDirty, insertArguments, buildErr := query.NewInsertBuilder(coordinator.renderer, "_schema_migrations").
		Columns("path", "version", "name", "kind", "checksum", "dirty", "applied_at", "service_version", "duration_ms", "operator", "instance_id", "backup_id").
		Values(name, version, migrationName, Kind(migrationName), checksum, true, time.Now().UTC().UnixMilli(), strings.TrimSpace(coordinator.config.ServiceVersion), 0, Operator(coordinator.config), InstanceID(coordinator.config), strings.TrimSpace(coordinator.BackupManager.BackupID())).Build()
	if buildErr != nil {
		return fmt.Errorf("build dirty migration record: %w", buildErr)
	}
	if _, err := coordinator.managementDatabase.ExecContext(ctx, insertDirty, insertArguments...); err != nil {
		return fmt.Errorf("record dirty migration: %w", err)
	}
	tx, err := coordinator.managementDatabase.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	if err := coordinator.engine.ConfigureMigrationTransaction(ctx, tx, coordinator.renderer, coordinator.databaseSchema, coordinator.config.DatabaseLockTimeout, coordinator.config.DatabaseStatementTimeout); err != nil {
		return err
	}
	for _, statement := range SplitSQLStatements(string(raw)) {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migration.failed: execute %s: %w", name, err)
		}
	}
	duration := time.Since(startedAt)
	completeMigration, completeArguments, buildErr := query.NewUpdateBuilder(coordinator.renderer, "_schema_migrations").
		Set("dirty", false).
		Set("duration_ms", duration.Milliseconds()).
		Set("applied_at", time.Now().UTC().UnixMilli()).
		Where(query.And(query.Equal("path", name), query.Equal("checksum", checksum))).Build()
	if buildErr != nil {
		return fmt.Errorf("build migration completion record: %w", buildErr)
	}
	if _, err := tx.ExecContext(ctx, completeMigration, completeArguments...); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func (coordinator *Coordinator) SetExpected(paths []string) error {
	expectedPaths := Names(paths)
	expectedChecksums := make(map[string]string, len(paths))
	for _, path := range paths {
		checksum, err := Checksum(path)
		if err != nil {
			return err
		}
		expectedChecksums[filepath.Base(path)] = checksum
	}
	coordinator.StatusReader.ReplaceExpected(expectedPaths, expectedChecksums)
	return nil
}
