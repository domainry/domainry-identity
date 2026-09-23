package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/domainry/domainry-audit-sdk/modulehost"
	"github.com/domainry/domainry-orm/query"
)

var moduleMigrationIdentityPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*(?:/[a-z][a-z0-9_-]*)?$`)

func (s *IdentityStore) ApplyOwnedMigrations(ctx context.Context, owner string, migrations []modulehost.SchemaMigration) error {
	if err := validateOwnedMigrations(owner, migrations); err != nil {
		return err
	}
	release, err := s.LockManager.Acquire(ctx, s.config)
	if err != nil {
		return err
	}
	defer release()
	if err := s.applyOwnedMigrationsLocked(ctx, owner, migrations); err != nil {
		return err
	}
	return nil
}

func (s *IdentityStore) ApplyOwnedMigrationsLocked(ctx context.Context, owner string, migrations []modulehost.SchemaMigration) error {
	if err := validateOwnedMigrations(owner, migrations); err != nil {
		return err
	}
	return s.applyOwnedMigrationsLocked(ctx, owner, migrations)
}

// ApplyNestedOwnedMigrations routes Metadata, Audit, and future nested module
// migrations through the embedding Runtime when Identity borrows its database.
func (s *IdentityStore) ApplyNestedOwnedMigrations(ctx context.Context, owner string, migrations []modulehost.SchemaMigration) error {
	return s.applyNestedOwnedMigrations(ctx, owner, migrations)
}

func validateOwnedMigrations(owner string, migrations []modulehost.SchemaMigration) error {
	if !moduleMigrationIdentityPattern.MatchString(strings.TrimSpace(owner)) {
		return fmt.Errorf("module migration owner is invalid")
	}
	for index, migration := range migrations {
		if migration.Version == 0 || !moduleMigrationIdentityPattern.MatchString(strings.TrimSpace(migration.Name)) || len(migration.Statements) == 0 {
			return fmt.Errorf("module migration %s[%d] is invalid", owner, index)
		}
		if index > 0 && migrations[index-1].Version >= migration.Version {
			return fmt.Errorf("module migrations for %s are not strictly ordered", owner)
		}
	}
	return nil
}

func (s *IdentityStore) applyOwnedMigrationsLocked(ctx context.Context, owner string, migrations []modulehost.SchemaMigration) error {

	if s.Coordinator == nil || s.Coordinator.Ledger == nil {
		return fmt.Errorf("module migration host ledger is unavailable")
	}
	if _, err := s.schemaDatabase().ExecContext(ctx, s.Coordinator.Ledger.SchemaSQL()); err != nil {
		return fmt.Errorf("prepare host migration ledger: %w", err)
	}
	for _, migration := range migrations {
		if err := s.applyOwnedMigration(ctx, owner, migration); err != nil {
			return err
		}
	}
	return nil
}

func (s *IdentityStore) applyOwnedMigration(ctx context.Context, owner string, migration modulehost.SchemaMigration) error {
	path := fmt.Sprintf("module_%s_%06d_%s", owner, migration.Version, strings.TrimSpace(migration.Name))
	checksum := hostModuleMigrationChecksum(migration)
	renderer := s.BuilderRenderer()
	queryValue, args, err := query.NewSelectBuilder(renderer, "_schema_migrations").
		Columns("checksum", "dirty").Where(query.Equal("path", path)).Build()
	if err != nil {
		return err
	}
	var applied string
	var dirty bool
	err = s.schemaDatabase().QueryRowContext(ctx, queryValue, args...).Scan(&applied, &dirty)
	if err == nil {
		if dirty {
			return fmt.Errorf("migration.dirty: %s", path)
		}
		if applied != checksum {
			return fmt.Errorf("migration.checksum_drift: %s", path)
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("inspect module migration %s: %w", path, err)
	}
	if s.config.EffectiveDatabaseMigrationMode() == "verify" {
		return fmt.Errorf("migration.pending: %s", path)
	}
	baseline, err := s.proveOwnedMigrationBaseline(ctx, migration.Baseline)
	if err != nil {
		return fmt.Errorf("migration.baseline_mismatch: %s: %w", path, err)
	}
	insert, insertArgs, err := query.NewInsertBuilder(renderer, "_schema_migrations").
		Columns("path", "version", "name", "kind", "checksum", "dirty", "applied_at", "duration_ms", "operator", "instance_id", "backup_id").
		Values(path, fmt.Sprint(migration.Version), migration.Name, "module:"+owner, checksum, !baseline, time.Now().UTC().Format(time.RFC3339), 0, "module", "identity", "").Build()
	if err != nil {
		return err
	}
	if _, err := s.schemaDatabase().ExecContext(ctx, insert, insertArgs...); err != nil {
		return fmt.Errorf("record module migration %s: %w", path, err)
	}
	if baseline {
		return nil
	}
	started := time.Now()
	tx, err := s.schemaDatabase().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin module migration %s: %w", path, err)
	}
	defer tx.Rollback()
	for _, statement := range migration.Statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migration.failed: execute %s: %w", path, err)
		}
	}
	complete, completeArgs, err := query.NewUpdateBuilder(renderer, "_schema_migrations").
		Set("dirty", false).Set("duration_ms", time.Since(started).Milliseconds()).Set("applied_at", time.Now().UTC().Format(time.RFC3339)).
		Where(query.And(query.Equal("path", path), query.Equal("checksum", checksum))).Build()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, complete, completeArgs...); err != nil {
		return fmt.Errorf("complete module migration %s: %w", path, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit module migration %s: %w", path, err)
	}
	return nil
}

// hostModuleMigrationChecksum is byte-identical to the embedding Runtime's
// host-owned migration ledger identity. Baseline structure is part of that
// identity even when no DDL statement needs to run, so a nested source module
// cannot reinterpret an already-applied host migration with a weaker checksum.
func hostModuleMigrationChecksum(migration modulehost.SchemaMigration) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%d\x00%s\x00", migration.Version, strings.TrimSpace(migration.Name))
	for _, statement := range migration.Statements {
		_, _ = fmt.Fprintf(hash, "%s\x00", statement)
	}
	if migration.Baseline != nil {
		for _, table := range migration.Baseline.Tables {
			_, _ = fmt.Fprintf(hash, "table\x00%s\x00", table.Name)
			for _, column := range table.Columns {
				_, _ = fmt.Fprintf(hash, "column\x00%s\x00%s\x00%t\x00%t\x00", column.Name, column.Type, column.Nullable, column.PrimaryKey)
			}
			for _, index := range table.Indexes {
				_, _ = fmt.Fprintf(hash, "index\x00%s\x00%t\x00%s\x00", index.Name, index.Unique, strings.Join(index.Columns, ","))
			}
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (s *IdentityStore) proveOwnedMigrationBaseline(ctx context.Context, baseline *modulehost.SchemaBaseline) (bool, error) {
	if baseline == nil || len(baseline.Tables) == 0 {
		return false, nil
	}
	found := 0
	for _, table := range baseline.Tables {
		columns, err := s.TableColumns(ctx, table.Name)
		if err != nil {
			return false, err
		}
		if len(columns) == 0 {
			continue
		}
		found++
		if len(columns) != len(table.Columns) {
			return false, fmt.Errorf("baseline schema mismatch for %s: columns=%d want=%d", table.Name, len(columns), len(table.Columns))
		}
		for _, column := range table.Columns {
			if !columns[column.Name] {
				return false, fmt.Errorf("baseline schema mismatch for %s: column %s is missing", table.Name, column.Name)
			}
		}
		indexes, err := s.TableIndexes(ctx, table.Name)
		if err != nil {
			return false, err
		}
		for _, index := range table.Indexes {
			if !indexes[index.Name] {
				return false, fmt.Errorf("baseline schema mismatch for %s: index %s is missing", table.Name, index.Name)
			}
		}
	}
	if found == 0 {
		return false, nil
	}
	if found != len(baseline.Tables) {
		return false, fmt.Errorf("partial baseline: found %d of %d owned tables", found, len(baseline.Tables))
	}
	return true, nil
}
